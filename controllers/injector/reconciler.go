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
	"fmt"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"

	porchv1alpha1 "github.com/GoogleContainerTools/kpt/porch/api/porch/v1alpha1"
	"github.com/go-logr/logr"
	"github.com/henderiw-nephio/nf-injector-controller/pkg/injector"
	"github.com/henderiw-nephio/nf-injector-controller/pkg/injectors"
	"github.com/henderiw-nephio/nf-injector-controller/pkg/ipam"
	"github.com/henderiw-nephio/nf-injector-controller/pkg/resource"
	"github.com/henderiw-nephio/nf-injector-controller/pkg/shared"
	"github.com/henderiw-nephio/nf-injector-controller/pkg/upf"
	infrav1alpha1 "github.com/nephio-project/nephio-controller-poc/apis/infra/v1alpha1"
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
	"sigs.k8s.io/kustomize/kyaml/yaml"
)

const (
	finalizer         = "injector.nephio.org/finalizer"
	upfConditionType  = "nf.nephio.org.UPFDeployment."
	ipamConditionType = "ipam.nephio.org.IPAMAllocation."
	readinessGateKind = "nf"

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

	upfConditions := unsatisfiedConditions(cr.Status.Conditions, upfConditionType)

	if len(upfConditions) > 0 {
		crName := types.NamespacedName{
			Namespace: cr.Namespace,
			Name:      cr.Name,
		}
		i := injector.New(&injector.Config{
			InjectorHandler: r.injectNFInfo,
			NamespacedName:  crName,
			Client:          r.Client,
		})

		// run the injector when the ipam readiness gate is set
		r.l.Info("injector running", "pr", cr.GetName())
		r.injectors.Run(i)
	}

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

func unsatisfiedConditions(conditions []porchv1alpha1.Condition, conditionType string) []porchv1alpha1.Condition {
	var uc []porchv1alpha1.Condition
	for _, c := range conditions {
		// TODO: make this smarter
		// for now, just check if it is True. It means we won't re-inject if some input changes,
		// unless someone flips the state
		if c.Status != porchv1alpha1.ConditionTrue && strings.HasPrefix(c.Type, conditionType) {
			uc = append(uc, c)
		}
	}

	return uc
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

	prConditions := convertConditions(pr.Status.Conditions)

	prResources := &porchv1alpha1.PackageRevisionResources{}
	if err := r.porchClient.Get(ctx, namespacedName, prResources); err != nil {
		return err
	}

	pkgBuf, err := porch.ResourcesToPackageBuffer(prResources.Spec.Resources)
	if err != nil {
		return err
	}

	// retrieve the corresponding FiveGCoreTopology resource
	fiveGCoreId := types.NamespacedName{Namespace: pr.Namespace}
	if n, ok := pr.Annotations["nf.nephio.org/topology"]; ok {
		fiveGCoreId.Name = n
	} else {
		return fmt.Errorf("missing %q annotation", "nf.nephio.org/topology")
	}

	var fiveGCore nfv1alpha1.FiveGCoreTopology
	if err := r.Get(ctx, fiveGCoreId, &fiveGCore); err != nil {
		return err
	}

	// find the corresponding UPFSpec in the FiveGCoreTopology resource
	clusterSetName, ok := pr.Annotations["nf.nephio.org/cluster-set"]
	if !ok {
		return fmt.Errorf("missing %q annotation", "nf.nephio.org/cluster-set")
	}

	var upfSpec *nfv1alpha1.UPFSpec
	for i := range fiveGCore.Spec.UPFs {
		if fiveGCore.Spec.UPFs[i].Name == clusterSetName {
			upfSpec = &fiveGCore.Spec.UPFs[i].UPF
			break
		}
	}

	if upfSpec == nil {
		return fmt.Errorf("did not find UPF %q in FiveGCoreTopology", clusterSetName)
	}

	// retrieve the corresponding UPFClass resource
	var upfClass nfv1alpha1.UPFClass
	if err := r.Get(ctx, client.ObjectKey{Name: upfSpec.UPFClassName}, &upfClass); err != nil {
		return err
	}

	// Option 1
	// find the UPF class -> they should contain a network reference
	// find the Cluster Context -> this hsould give us info on interface, etc
	// allocate IP(s) based on this information

	existingIPAllocations := map[string]int{}
	existingUPFDeployments := map[string]int{}

	// for now we only support exactly one N3, N4, N6, and zero or one N9
	if len(upfSpec.N3) != 1 {
		return fmt.Errorf("exactly one N3 endpoint should be defined")
	}

	if len(upfSpec.N4) != 1 {
		return fmt.Errorf("exactly one N4 endpoint should be defined")
	}

	if len(upfSpec.N6) != 1 {
		return fmt.Errorf("exactly one N6 endpoint should be defined")
	}

	if len(upfSpec.N9) > 1 {
		return fmt.Errorf("at most one N9 endpoint should be defined")
	}

	n6pool := upfSpec.N6[0].UEPool

	if n6pool.NetworkInstance == nil || *n6pool.NetworkInstance == "" {
		return fmt.Errorf("N6.NetworkInstance is required")
	}

	if n6pool.NetworkName == nil || *n6pool.NetworkName == "" {
		return fmt.Errorf("N6.NetworkName is required")
	}

	endpoints := map[string]*nfv1alpha1.Endpoint{
		"n3": &upfSpec.N3[0],
		"n4": &upfSpec.N4[0],
		"n6": &upfSpec.N6[0].Endpoint,
		"n9": nil,
	}
	if len(upfSpec.N9) > 0 {
		endpoints["n9"] = &upfSpec.N9[0]
	}

	namespace := "default"
	var clusterContext *infrav1alpha1.ClusterContext
	for i, rn := range pkgBuf.Nodes {
		if rn.GetApiVersion() == "ipam.nephio.org/v1alpha1" && rn.GetKind() == "IPAllocation" {
			existingIPAllocations[rn.GetName()] = i
		}
		if rn.GetApiVersion() == "nf.nephio.org/v1alpha1" && rn.GetKind() == "UPFDeployment" {
			existingUPFDeployments[rn.GetName()] = i
			namespace = rn.GetNamespace()
		}
		if rn.GetApiVersion() == "infra.nephio.org/v1alpha1" && rn.GetKind() == "ClusterContext" {
			if clusterContext != nil {
				return fmt.Errorf("only one ClusterContext can be in the package")
			}
			nStr := rn.MustString()
			clusterContext = &infrav1alpha1.ClusterContext{}
			if err := yaml.Unmarshal([]byte(nStr), clusterContext); err != nil {
				return err
			}
		}
	}

	if clusterContext == nil {
		return fmt.Errorf("no ClusterContext found in the package")
	}

	if clusterContext.Spec.SiteCode == nil || *clusterContext.Spec.SiteCode == "" {
		return fmt.Errorf("CluterContext.Spec.SiteCode is required")
	}

	if len(existingUPFDeployments) == 0 {
		return fmt.Errorf("no existing UPFDeployment found in the package")
	}

	if len(existingUPFDeployments) > 1 {
		return fmt.Errorf("only a single UPFDeployment should be in the package")
	}

	// create an IP Allocation per endpoint and per pool
	for epName, ep := range endpoints {
		if ep.NetworkInstance == nil || ep.NetworkName == nil || *ep.NetworkInstance != "" || *ep.NetworkName != "" {
			// probably should log something
			continue
		}
		ipAllocName := strings.Join([]string{"upf", *clusterContext.Spec.SiteCode}, "-") // TODO need more discussion
		ipamResourceName := strings.Join([]string{ipAllocName, epName}, "-")
		ipAlloc, err := ipam.BuildIPAMAllocation(
			ipAllocName,
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
		if i, ok := existingIPAllocations[ipamResourceName]; ok {
			// exits -> replace
			pkgBuf.Nodes[i] = ipAlloc
		} else {
			// add new entry
			pkgBuf.Nodes = append(pkgBuf.Nodes, ipAlloc)
		}

		conditionType := fmt.Sprintf("%s.%s.%s.Injected", ipamConditionType, ipamResourceName, namespace)
		meta.SetStatusCondition(prConditions, metav1.Condition{Type: conditionType, Status: metav1.ConditionFalse,
			Reason: "PendingInjection", Message: "Awaiting IP allocation and injection"})
	}

	ps, err := strconv.Atoi(*n6pool.PrefixSize)
	if err != nil {
		return err
	}
	ipPoolAllocName := strings.Join([]string{"upf", *clusterContext.Spec.SiteCode}, "-")
	ipAlloc, err := ipam.BuildIPAMAllocation(
		ipPoolAllocName,
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
	if i, ok := existingIPAllocations[strings.Join([]string{ipPoolAllocName, "n6pool"}, "-")]; ok {
		// exits -> replace
		pkgBuf.Nodes[i] = ipAlloc
	} else {
		// add new entry
		pkgBuf.Nodes = append(pkgBuf.Nodes, ipAlloc)
	}

	upfDeploymentName := strings.Join([]string{"upf", *clusterContext.Spec.SiteCode}, "-")
	upfDeployment, err := upf.BuildUPFDeployment(
		types.NamespacedName{
			Name:      upfDeploymentName,
			Namespace: namespace,
		},
		upf.BuildUPFDeploymentSpec(endpoints, upfSpec.N6[0].DNN, upfSpec.Capacity),
	)
	if err != nil {
		return errors.Wrap(err, "cannot build upfDeployment rnode")
	}
	conditionType := fmt.Sprintf("%s.%s.%s.Injected", upfConditionType, upfDeploymentName, namespace)
	if i, ok := existingUPFDeployments[upfDeploymentName]; ok {
		n := pkgBuf.Nodes[i]
		// set the spec on the one in the package to match our spec
		field := upfDeployment.Field("spec")
		if err := n.SetMapField(field.Value, "spec"); err != nil {
			r.l.Error(err, "could not set UPFDeployment.Spec")
			meta.SetStatusCondition(prConditions, metav1.Condition{Type: conditionType, Status: metav1.ConditionFalse,
				Reason: "ResourceSpecErr", Message: err.Error()})
			return err
		}

		meta.SetStatusCondition(prConditions, metav1.Condition{Type: conditionType, Status: metav1.ConditionTrue,
			Reason: "ResourceInjected", Message: fmt.Sprintf("injected from FiveGCoreTopology %q UPF name %q",
				fiveGCore.Name, clusterSetName)})

	}

	newResources, err := porch.CreateUpdatedResources(prResources.Spec.Resources, pkgBuf)
	if err != nil {
		return errors.Wrap(err, "cannot update package revision resources")
	}
	prResources.Spec.Resources = newResources
	if err = r.porchClient.Update(ctx, prResources); err != nil {
		return err
	}

	pr.Status.Conditions = unconvertConditions(prConditions)
	/* holding off on readiness gates right now
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
	*/

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

// copied from package deployment controller - clearly we need some libraries or
// to directly use the K8s meta types
func convertConditions(conditions []porchv1alpha1.Condition) *[]metav1.Condition {
	var result []metav1.Condition
	for _, c := range conditions {
		result = append(result, metav1.Condition{
			Type:    c.Type,
			Reason:  c.Reason,
			Status:  metav1.ConditionStatus(c.Status),
			Message: c.Message,
		})
	}
	return &result
}

func unconvertConditions(conditions *[]metav1.Condition) []porchv1alpha1.Condition {
	var prConditions []porchv1alpha1.Condition
	for _, c := range *conditions {
		prConditions = append(prConditions, porchv1alpha1.Condition{
			Type:    c.Type,
			Reason:  c.Reason,
			Status:  porchv1alpha1.ConditionStatus(c.Status),
			Message: c.Message,
		})
	}

	return prConditions
}
