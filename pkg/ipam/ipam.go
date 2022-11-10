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

func getIPAllocation(nfName string, epName types.NamespacedName, spec ipamv1alpha1.IPAllocationSpec) string {
	x :=  &ipamv1alpha1.IPAllocation{
		TypeMeta: metav1.TypeMeta{
			Kind:       "IPAllocation",
			APIVersion: "ipam.nephio.org/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      strings.Join([]string{nfName, epName.Name}, "-"),
			Namespace: epName.Namespace,
			Labels: map[string]string{
				ipamv1alpha1.NephioInterfaceKey: epName.Name,
			},
		},
		Spec: spec,
	}
	b := new(strings.Builder)
	p := printers.YAMLPrinter{}
	p.PrintObj(x, b)
	return b.String()
}

func BuildIPAMAllocationFn(nfName string, epName types.NamespacedName, spec ipamv1alpha1.IPAllocationSpec) (*fn.KubeObject, error) {
	x := getIPAllocation(nfName, epName, spec)
	return fn.ParseKubeObject([]byte(x))
}

func BuildIPAMAllocation(nfName string, epName types.NamespacedName, spec ipamv1alpha1.IPAllocationSpec) (*kyaml.RNode, error) {
	x := getIPAllocation(nfName, epName, spec)
	return kyaml.Parse(x)
}
