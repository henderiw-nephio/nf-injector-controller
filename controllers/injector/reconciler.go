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

	kptfile "github.com/GoogleContainerTools/kpt/pkg/api/kptfile/v1"
	porchv1alpha1 "github.com/GoogleContainerTools/kpt/porch/api/porch/v1alpha1"
	"github.com/go-logr/logr"
	"github.com/henderiw-nephio/nf-injector-controller/pkg/injectors"
	"github.com/henderiw-nephio/nf-injector-controller/pkg/ipam"
	"github.com/henderiw-nephio/nf-injector-controller/pkg/resource"
	"github.com/henderiw-nephio/nf-injector-controller/pkg/shared"
	"github.com/henderiw-nephio/nf-injector-controller/pkg/upf"
	infrav1alpha1 "github.com/nephio-project/nephio-controller-poc/apis/infra/v1alpha1"
	"github.com/nephio-project/nephio-controller-poc/pkg/porch"
	nfv1alpha1 "github.com/nephio-project/nephio-pocs/nephio-5gc-controller/apis/nf/v1alpha1"
	ipamv1alpha1 "github.com/nokia/k8s-ipam/apis/ipam/v1alpha1"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/kustomize/kyaml/kio"
	kyaml "sigs.k8s.io/kustomize/kyaml/yaml"
)

const (
	finalizer         = "injector.nephio.org/finalizer"
	upfConditionType  = "nf.nephio.org.UPFDeployment"
	ipamConditionType = "ipam.nephio.org.IPAMAllocation"
	//readinessGateKind = "nf"

	//defaultNetworkInstance = "vpc-1"
	//defaultKind            = "nad"
	//defaultCniVersion      = "0.3.1"
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
		Client:      mgr.GetClient(),
		Scheme:      mgr.GetScheme(),
		porchClient: options.PorchClient,

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
	client.Client
	porchClient  client.Client
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

	r.l.Info("cr conditons", "conditions", cr.Status.Conditions)

	upfConditions := unsatisfiedConditions(cr.Status.Conditions, upfConditionType)

	if len(upfConditions) > 0 {
		crName := types.NamespacedName{
			Namespace: cr.Namespace,
			Name:      cr.Name,
		}

		r.l.Info("injector running", "pr", cr.GetName())
		if err := r.injectNFInfo(ctx, crName); err != nil {
			r.l.Error(err, "injection error")
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

/*
func hasReadinessGate(gates []porchv1alpha1.ReadinessGate, gate string) bool {
	for i := range gates {
		g := gates[i]
		if g.ConditionType == gate {
			return true
		}
	}
	return false
}
*/

func unsatisfiedConditions(conditions []porchv1alpha1.Condition, conditionType string) []porchv1alpha1.Condition {
	var uc []porchv1alpha1.Condition
	for _, c := range conditions {
		// TODO: make this smarter
		// for now, just check if it is True. It means we won't re-inject if some input changes,
		// unless someone flips the state
		if c.Status != porchv1alpha1.ConditionTrue && strings.HasPrefix(c.Type, conditionType+".") {
			uc = append(uc, c)
		}
	}

	return uc
}

/*
func hasCondition(conditions []porchv1alpha1.Condition, conditionType string) (*porchv1alpha1.Condition, bool) {
	for i := range conditions {
		c := conditions[i]
		if c.Type == conditionType {
			return &c, true
		}
	}
	return nil, false
}
*/

func (r *reconciler) injectNFInfo(ctx context.Context, namespacedName types.NamespacedName) error {
	r.l = log.FromContext(ctx)
	r.l.Info("injector function", "name", namespacedName.String())

	origPr := &porchv1alpha1.PackageRevision{}
	if err := r.porchClient.Get(ctx, namespacedName, origPr); err != nil {
		return err
	}

	pr := origPr.DeepCopy()

	prConditions := convertConditions(pr.Status.Conditions)

	prResources, pkgBuf, err := r.injectNFResources(ctx, namespacedName, prConditions, pr)
	if err != nil {
		if pkgBuf == nil {
			return err
		}
		// for now just assume the error applies to all UPFDeployments
		// we should only have one for the proof-of-concept
		for _, c := range *prConditions {
			if !strings.HasPrefix(c.Type, upfConditionType) {
				continue
			}
			if meta.IsStatusConditionTrue(*prConditions, c.Type) {
				continue
			}
			meta.SetStatusCondition(prConditions, metav1.Condition{Type: c.Type, Status: metav1.ConditionFalse,
				Reason: "ErrorDuringInjection", Message: err.Error()})

		}
	}

	pr.Status.Conditions = unconvertConditions(prConditions)

	// conditions are stored in the Kptfile right now
	for i, n := range pkgBuf.Nodes {
		if n.GetKind() == "Kptfile" {
			// we need to update the status
			nStr := n.MustString()
			var kf kptfile.KptFile
			if err := kyaml.Unmarshal([]byte(nStr), &kf); err != nil {
				return err
			}
			if kf.Status == nil {
				kf.Status = &kptfile.Status{}
			}
			kf.Status.Conditions = conditionsToKptfile(prConditions)

			kfBytes, _ := kyaml.Marshal(kf)
			node := kyaml.MustParse(string(kfBytes))
			pkgBuf.Nodes[i] = node
		}
	}

	newResources, err := porch.CreateUpdatedResources(prResources.Spec.Resources, pkgBuf)
	if err != nil {
		return errors.Wrap(err, "cannot update package revision resources")
	}
	prResources.Spec.Resources = newResources
	if err = r.porchClient.Update(ctx, prResources); err != nil {
		return err
	}

	return nil
}

func (r *reconciler) injectNFResources(ctx context.Context, namespacedName types.NamespacedName,
	prConditions *[]metav1.Condition,
	pr *porchv1alpha1.PackageRevision) (*porchv1alpha1.PackageRevisionResources, *kio.PackageBuffer, error) {

	prResources := &porchv1alpha1.PackageRevisionResources{}
	if err := r.porchClient.Get(ctx, namespacedName, prResources); err != nil {
		return nil, nil, err
	}

	pkgBuf, err := porch.ResourcesToPackageBuffer(prResources.Spec.Resources)
	if err != nil {
		return prResources, nil, err
	}

	// retrieve the corresponding FiveGCoreTopology resource
	fiveGCoreId := types.NamespacedName{Namespace: pr.Namespace}
	if n, ok := pr.Annotations["nf.nephio.org/topology"]; ok {
		fiveGCoreId.Name = n
	} else {
		return prResources, pkgBuf, fmt.Errorf("missing %q annotation", "nf.nephio.org/topology")
	}

	var fiveGCore nfv1alpha1.FiveGCoreTopology
	if err := r.Get(ctx, fiveGCoreId, &fiveGCore); err != nil {
		return prResources, pkgBuf, err
	}

	// find the corresponding UPFSpec in the FiveGCoreTopology resource
	clusterSetName, ok := pr.Annotations["nf.nephio.org/cluster-set"]
	if !ok {
		return prResources, pkgBuf, fmt.Errorf("missing %q annotation", "nf.nephio.org/cluster-set")
	}

	var upfSpec *nfv1alpha1.UPFSpec
	for i := range fiveGCore.Spec.UPFs {
		if fiveGCore.Spec.UPFs[i].Name == clusterSetName {
			upfSpec = &fiveGCore.Spec.UPFs[i].UPF
			break
		}
	}

	if upfSpec == nil {
		return prResources, pkgBuf, fmt.Errorf("did not find UPF %q in FiveGCoreTopology", clusterSetName)
	}

	// retrieve the corresponding UPFClass resource
	var upfClass nfv1alpha1.UPFClass
	if err := r.Get(ctx, client.ObjectKey{Name: upfSpec.UPFClassName}, &upfClass); err != nil {
		return prResources, pkgBuf, err
	}

	// Option 1
	// find the UPF class -> they should contain a network reference
	// find the Cluster Context -> this hsould give us info on interface, etc
	// allocate IP(s) based on this information

	existingIPAllocations := map[string]int{}
	existingUPFDeployments := map[string]int{}

	// for now we only support exactly one N3, N4, N6, and zero or one N9
	if len(upfSpec.N3) != 1 {
		return prResources, pkgBuf, fmt.Errorf("exactly one N3 endpoint should be defined")
	}

	if len(upfSpec.N4) != 1 {
		return prResources, pkgBuf, fmt.Errorf("exactly one N4 endpoint should be defined")
	}

	if len(upfSpec.N6) != 1 {
		return prResources, pkgBuf, fmt.Errorf("exactly one N6 endpoint should be defined")
	}

	if len(upfSpec.N9) > 1 {
		return prResources, pkgBuf, fmt.Errorf("at most one N9 endpoint should be defined")
	}

	n6pool := upfSpec.N6[0].UEPool

	if n6pool.NetworkInstance == nil || *n6pool.NetworkInstance == "" {
		return prResources, pkgBuf, fmt.Errorf("N6.NetworkInstance is required")
	}

	if n6pool.NetworkName == nil || *n6pool.NetworkName == "" {
		return prResources, pkgBuf, fmt.Errorf("N6.NetworkName is required")
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
			if rn.GetNamespace() != "" {
				namespace = rn.GetNamespace()
			}
		}
		if rn.GetApiVersion() == "infra.nephio.org/v1alpha1" && rn.GetKind() == "ClusterContext" {
			clusterContext = &infrav1alpha1.ClusterContext{}
			fillClusterContext(rn, clusterContext)
		}
	}

	if clusterContext == nil {
		return prResources, pkgBuf, fmt.Errorf("ClusterContext is required")
	}

	if clusterContext.Spec.SiteCode == nil || *clusterContext.Spec.SiteCode == "" {
		return prResources, pkgBuf, fmt.Errorf("CluterContext.Spec.SiteCode is required")
	}

	if len(existingUPFDeployments) == 0 {
		return prResources, pkgBuf, fmt.Errorf("no existing UPFDeployment found in the package")
	}

	if len(existingUPFDeployments) > 1 {
		return prResources, pkgBuf, fmt.Errorf("only a single UPFDeployment should be in the package")
	}

	// create an IP Allocation per endpoint and per pool
	for epName, ep := range endpoints {
		if ep == nil || ep.NetworkInstance == nil || ep.NetworkName == nil || *ep.NetworkInstance == "" || *ep.NetworkName == "" {
			r.l.Info("skipping", "epName", epName, "ep", ep)
			continue
		}
		r.l.Info("injecting IPAllocation for endpoint", "epName", epName, "ep", ep)
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
			return prResources, pkgBuf, errors.Wrap(err, "cannot get ipalloc rnode")
		}
		if i, ok := existingIPAllocations[ipamResourceName]; ok {
			r.l.Info("replacing existing IPAllocation", "ipamResourceName", ipamResourceName, "ipAlloc", ipAlloc)
			// exits -> replace
			pkgBuf.Nodes[i] = ipAlloc
		} else {
			r.l.Info("adding new IPAllocation", "ipamResourceName", ipamResourceName, "ipAlloc", ipAlloc)
			// add new entry
			pkgBuf.Nodes = append(pkgBuf.Nodes, ipAlloc)
		}

		conditionType := fmt.Sprintf("%s.%s.%s.Injected", ipamConditionType, ipamResourceName, namespace)
		r.l.Info("setting condition", "conditionType", conditionType)
		meta.SetStatusCondition(prConditions, metav1.Condition{Type: conditionType, Status: metav1.ConditionFalse,
			Reason: "PendingInjection", Message: "Awaiting IP allocation and injection"})
	}

	ps, err := strconv.Atoi(*n6pool.PrefixSize)
	if err != nil {
		return prResources, pkgBuf, err
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
		return prResources, pkgBuf, errors.Wrap(err, "cannot get ipalloc rnode")
	}
	if i, ok := existingIPAllocations[strings.Join([]string{ipPoolAllocName, "n6pool"}, "-")]; ok {
		r.l.Info("replacing existing IPAllocation", "ipamResourceName", "n6pool", "ipAlloc", ipAlloc)
		pkgBuf.Nodes[i] = ipAlloc
	} else {
		r.l.Info("adding new IPAllocation", "ipamResourceName", "n6pool", "ipAlloc", ipAlloc)
		pkgBuf.Nodes = append(pkgBuf.Nodes, ipAlloc)
	}

	conditionType := fmt.Sprintf("%s.%s.%s.Injected", ipamConditionType, "n6pool", namespace)
		r.l.Info("setting condition", "conditionType", conditionType)
		meta.SetStatusCondition(prConditions, metav1.Condition{Type: conditionType, Status: metav1.ConditionFalse,
			Reason: "PendingInjection", Message: "Awaiting IP allocation and injection"})

	upfDeploymentName := strings.Join([]string{"upf", *clusterContext.Spec.SiteCode}, "-")
	upfDeployment, err := upf.BuildUPFDeployment(
		types.NamespacedName{
			Name:      upfDeploymentName,
			Namespace: namespace,
		},
		upf.BuildUPFDeploymentSpec(endpoints, upfSpec.N6[0].DNN, upfSpec.Capacity),
	)
	if err != nil {
		return prResources, pkgBuf, errors.Wrap(err, "cannot build upfDeployment rnode")
	}
	
	if i, ok := existingUPFDeployments[upfDeploymentName]; ok {
		r.l.Info("replacing existing UPFDeployment", "upfDeploymentName", upfDeploymentName, "upfDeployment", upfDeployment)
		n := pkgBuf.Nodes[i]
		// set the spec on the one in the package to match our spec
		field := upfDeployment.Field("spec")
		if err := n.SetMapField(field.Value, "spec"); err != nil {
			r.l.Error(err, "could not set UPFDeployment.Spec")
			meta.SetStatusCondition(prConditions, metav1.Condition{Type: conditionType, Status: metav1.ConditionFalse,
				Reason: "ResourceSpecErr", Message: err.Error()})
			return prResources, pkgBuf, err
		}
	}
	conditionType = fmt.Sprintf("%s.%s.%s.Injected", upfConditionType, upfDeploymentName, namespace)
	r.l.Info("setting upfdeployment condition", "conditionType", conditionType)
		meta.SetStatusCondition(prConditions, metav1.Condition{Type: conditionType, Status: metav1.ConditionTrue,
			Reason: "ResourceInjected", Message: fmt.Sprintf("injected from FiveGCoreTopology %q UPF name %q",
				fiveGCore.Name, clusterSetName)})

	return prResources, pkgBuf, nil
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

func conditionsToKptfile(conditions *[]metav1.Condition) []kptfile.Condition {
	var prConditions []kptfile.Condition
	for _, c := range *conditions {
		prConditions = append(prConditions, kptfile.Condition{
			Type:    c.Type,
			Reason:  c.Reason,
			Status:  kptfile.ConditionStatus(c.Status),
			Message: c.Message,
		})
	}
	return prConditions
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

func fillClusterContext(rn *kyaml.RNode, cc *infrav1alpha1.ClusterContext) {
	t := upf.MustGetValue(rn, "spec.cniConfig.cniType")
	i := upf.MustGetValue(rn, "spec.cniConfig.masterInterface")
	s := upf.MustGetValue(rn, "spec.siteCode")
	cc.Spec = infrav1alpha1.ClusterContextSpec{
		CNIConfig: &infrav1alpha1.CNIConfig{
			CNIType:         t,
			MasterInterface: i,
		},
		SiteCode: &s,
	}
}
