package ipam

import (
	"strings"

	"k8s.io/cli-runtime/pkg/printers"
	kyaml "sigs.k8s.io/kustomize/kyaml/yaml"

	//corev1 "k8s.io/api/core/v1"
	"github.com/GoogleContainerTools/kpt-functions-sdk/go/fn"
	ipamv1alpha1 "github.com/nokia/k8s-ipam/apis/ipam/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func BuildIPAMAllocationFn(nsName types.NamespacedName, spec ipamv1alpha1.IPAllocationSpec) (*fn.KubeObject, error) {
	ns := &ipamv1alpha1.IPAllocation{
		TypeMeta: metav1.TypeMeta{
			Kind:       "IPAllocation",
			APIVersion: "v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      nsName.Name,
			Namespace: nsName.Namespace,
		},
		Spec: spec,
	}

	b := new(strings.Builder)
	p := printers.YAMLPrinter{}
	p.PrintObj(ns, b)

	return fn.ParseKubeObject([]byte(b.String()))
}

func BuildIPAMAllocation(nsName types.NamespacedName, spec ipamv1alpha1.IPAllocationSpec) (*kyaml.RNode, error) {
	ns := &ipamv1alpha1.IPAllocation{
		TypeMeta: metav1.TypeMeta{
			Kind:       "IPAllocation",
			APIVersion: "v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      nsName.Name,
			Namespace: nsName.Namespace,
		},
		Spec: spec,
	}

	b := new(strings.Builder)
	p := printers.YAMLPrinter{}
	p.PrintObj(ns, b)

	return kyaml.Parse(b.String())
}
