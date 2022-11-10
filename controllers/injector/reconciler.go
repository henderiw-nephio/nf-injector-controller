/*
Copyright 2022 Nokia.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package injector

import (
	"context"
	"strconv"
	"strings"
	"time"

	porchv1alpha1 "github.com/GoogleContainerTools/kpt/porch/api/porch/v1alpha1"
	"github.com/go-logr/logr"
	"github.com/henderiw-nephio/nf-injector-controller/pkg/injector"
	"github.com/henderiw-nephio/nf-injector-controller/pkg/injectors"
	"github.com/henderiw-nephio/nf-injector-controller/pkg/ipam"
	"github.com/henderiw-nephio/nf-injector-controller/pkg/resource"
	"github.com/henderiw-nephio/nf-injector-controller/pkg/shared"
	"github.com/henderiw-nephio/nf-injector-controller/pkg/upf"
	"github.com/nephio-project/nephio-controller-poc/pkg/porch"
	nfv1alpha1 "github.com/nephio-project/nephio-pocs/nephio-5gc-controller/apis/nf/v1alpha1"
	ipamv1alpha1 "github.com/nokia/k8s-ipam/apis/ipam/v1alpha1"
	"github.com/nokia/k8s-ipam/pkg/alloc/allocpb"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	finalizer              = "injector.nephio.org/finalizer"
	readinessGateKind      = "nf"
	defaultNetworkInstance = "vpc-1"
	defaultKind            = "nad"
	defaultCniVersion      = "0.3.1"
	// errors
	//errGetCr        = "cannot get resource"
	//errUpdateStatus = "cannot update status"

	//reconcileFailed = "reconcile failed"
)

//+kubebuilder:rbac:groups=porch.kpt.dev,resources=packagerevisions,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=porch.kpt.dev,resources=packagerevisions/status,verbs=get;update;patch

// SetupWithManager sets up the controller with the Manager.
func Setup(mgr ctrl.Manager, options *shared.Options) error {
	r := &reconciler{
		kind:        readinessGateKind,
		Client:      mgr.GetClient(),
		Scheme:      mgr.GetScheme(),
		porchClient: options.PorchClient,
		allocCLient: options.AllocClient,

		injectors:    injectors.New(),
		pollInterval: options.Poll,
		finalizer:    resource.NewAPIFinalizer(mgr.GetClient(), finalizer),
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&porchv1alpha1.PackageRevision{}).
		Complete(r)
}

// reconciler reconciles a NetworkInstance object
type reconciler struct {
	kind string
	client.Client
	porchClient  client.Client
	allocCLient  allocpb.AllocationClient
	Scheme       *runtime.Scheme
	injectors    injectors.Injectors
	pollInterval time.Duration
	finalizer    *resource.APIFinalizer

	l logr.Logger
}

func (r *reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.l = log.FromContext(ctx)
	r.l.Info("reconcile", "req", req)

	cr := &porchv1alpha1.PackageRevision{}
	if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
		// There's no need to requeue if we no longer exist. Otherwise we'll be
		// requeued implicitly because we return an error.
		if resource.IgnoreNotFound(err) != nil {
			r.l.Error(err, "cannot get resource")
			return ctrl.Result{}, errors.Wrap(resource.IgnoreNotFound(err), "cannot get resource")
		}
		return ctrl.Result{}, nil
	}

	crName := types.NamespacedName{
		Namespace: cr.Namespace,
		Name:      cr.Name,
	}
	i := injector.New(&injector.Config{
		InjectorHandler: r.injectNFInfo,
		NamespacedName:  crName,
		Client:          r.Client,
	})

	hasReadinessGateForKind := hasReadinessGate(cr.Spec.ReadinessGates, r.kind)
	// if no IPAM readiness gate, delete the injector if it existed or not
	// we can stop the reconciliation in this case since there is nothing more to do
	if !hasReadinessGateForKind {
		r.injectors.Stop(i)
		r.l.Info("injector stopped", "pr", cr.GetName())
		return ctrl.Result{}, nil
	}

	// run the injector when the ipam readiness gate is set
	r.l.Info("injector running", "pr", cr.GetName())
	r.injectors.Run(i)

	return ctrl.Result{}, nil
}

func hasReadinessGate(gates []porchv1alpha1.ReadinessGate, gate string) bool {
	for i := range gates {
		g := gates[i]
		if g.ConditionType == gate {
			return true
		}
	}
	return false
}

func hasCondition(conditions []porchv1alpha1.Condition, conditionType string) (*porchv1alpha1.Condition, bool) {
	for i := range conditions {
		c := conditions[i]
		if c.Type == conditionType {
			return &c, true
		}
	}
	return nil, false
}

func (r *reconciler) injectNFInfo(ctx context.Context, namespacedName types.NamespacedName) error {
	r.l = log.FromContext(ctx)
	r.l.Info("injector function", "name", namespacedName.String())

	origPr := &porchv1alpha1.PackageRevision{}
	if err := r.porchClient.Get(ctx, namespacedName, origPr); err != nil {
		return err
	}

	pr := origPr.DeepCopy()

	prResources := &porchv1alpha1.PackageRevisionResources{}
	if err := r.porchClient.Get(ctx, namespacedName, prResources); err != nil {
		return err
	}

	pkgBuf, err := porch.ResourcesToPackageBuffer(prResources.Spec.Resources)
	if err != nil {
		return err
	}

	// Option 1
	// find the UPF class -> they should contain a network reference
	// find the Cluster Context -> this hsould give us info on interface, etc
	// allocate IP(s) based on this information

	n6pool := nfv1alpha1.Pool{}
	endpoints := map[string]*nfv1alpha1.Endpoint{
		"n3": nil,
		"n4": nil,
		"n6": nil,
		"n9": nil,
	}
	namespace := "default"
	dnn := ""
	capacity := nfv1alpha1.UPFCapacity{}
	region := ""
	for _, rn := range pkgBuf.Nodes {
		if rn.GetApiVersion() == "nf.nephio.org/v1alpha1" && rn.GetKind() == "UPF" {
			namespace = rn.GetNamespace()
			if region, err = upf.GetRegion(rn); err != nil {
				return err
			}
			dnn = upf.GetDnn(rn)
			capacity = upf.GetCapacity(rn)
			for epName := range endpoints {
				if epName == "n6" {
					// it is assumed n6 is needed this i why an err is returned, when n6 is not found
					n6ep, err := upf.GetN6Endpoint(epName, rn)
					if err != nil {
						return err
					}
					endpoints[epName] = &n6ep.Endpoint
					n6pool = n6ep.UEPool
				} else {
					ep, err := upf.GetEndpoint(epName, rn)
					if err != nil {
						return err
					}
					endpoints[epName] = ep
				}
			}
		}
	}

	// create an IP Allocation per endpoint and per pool
	for epName, ep := range endpoints {
		if *ep.NetworkInstance != "" && *ep.NetworkName != "" {
			ipAlloc, err := ipam.BuildIPAMAllocation(
				strings.Join([]string{"upf", region}, "-"),
				types.NamespacedName{
					Name:      epName,
					Namespace: namespace,
				},
				ipamv1alpha1.IPAllocationSpec{
					PrefixKind: string(ipamv1alpha1.PrefixKindNetwork),
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							ipamv1alpha1.NephioNetworkInstanceKey: *ep.NetworkInstance,
							ipamv1alpha1.NephioNetworkNameKey:     *ep.NetworkName,
						},
					},
				})
			if err != nil {
				return errors.Wrap(err, "cannot get ipalloc rnode")
			}
			pkgBuf.Nodes = append(pkgBuf.Nodes, ipAlloc)
		}
	}

	ps, err := strconv.Atoi(*n6pool.PrefixSize)
	if err != nil {
		return err
	}
	ipAlloc, err := ipam.BuildIPAMAllocation(
		strings.Join([]string{"upf", region}, "-"),
		types.NamespacedName{
			Name:      "n6pool",
			Namespace: namespace,
		},
		ipamv1alpha1.IPAllocationSpec{
			PrefixKind:   string(ipamv1alpha1.PrefixKindPool),
			PrefixLength: uint8(ps),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					ipamv1alpha1.NephioNetworkInstanceKey: *n6pool.NetworkInstance,
					ipamv1alpha1.NephioNetworkNameKey:     *n6pool.NetworkName,
				},
			},
		})
	if err != nil {
		return errors.Wrap(err, "cannot get ipalloc rnode")
	}
	pkgBuf.Nodes = append(pkgBuf.Nodes, ipAlloc)

	updDeployment, err := upf.BuildUPFDeployment(
		types.NamespacedName{
			Name:      strings.Join([]string{"upf", region}, "-"),
			Namespace: namespace,
		},
		upf.BuildUPFDeploymentSpec(endpoints, dnn, capacity),
	)
	if err != nil {
		return errors.Wrap(err, "cannot build upfDeployment rnode")
	}
	pkgBuf.Nodes = append(pkgBuf.Nodes, updDeployment)

	newResources, err := porch.CreateUpdatedResources(prResources.Spec.Resources, pkgBuf)
	if err != nil {
		return errors.Wrap(err, "cannot update package revision resources")
	}
	prResources.Spec.Resources = newResources
	if err = r.porchClient.Update(ctx, prResources); err != nil {
		return err
	}

	hasReadinessGateForKind := hasReadinessGate(pr.Spec.ReadinessGates, r.kind)
	kindCondition, found := hasCondition(pr.Status.Conditions, r.kind)
	if !hasReadinessGateForKind {
		pr.Spec.ReadinessGates = append(pr.Spec.ReadinessGates, porchv1alpha1.ReadinessGate{
			ConditionType: "bar",
		})
	}

	// If the condition is not already set on the PackageRevision, set it. Otherwise just
	// make sure that the status is "True".
	if !found {
		pr.Status.Conditions = append(pr.Status.Conditions, porchv1alpha1.Condition{
			Type:   "foo",
			Status: porchv1alpha1.ConditionTrue,
		})
	} else {
		kindCondition.Status = porchv1alpha1.ConditionTrue
	}

	// If nothing changed, then no need to update.
	// TODO: For some reason using equality.Semantic.DeepEqual and the full PackageRevision always reports a diff.
	// We should find out why.
	if equality.Semantic.DeepEqual(origPr.Spec.ReadinessGates, pr.Spec.ReadinessGates) &&
		equality.Semantic.DeepEqual(origPr.Status, pr.Status) {
		return nil
	}

	if err := r.Update(ctx, pr); err != nil {
		return errors.Wrap(err, "cannot update packagerevision")
	}

	return nil
}
