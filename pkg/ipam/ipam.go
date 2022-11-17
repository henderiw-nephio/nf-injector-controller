package ipam

import (
	"strconv"
	"strings"

	"k8s.io/cli-runtime/pkg/printers"
	"sigs.k8s.io/kustomize/kyaml/utils"
	kyaml "sigs.k8s.io/kustomize/kyaml/yaml"

	//corev1 "k8s.io/api/core/v1"
	"github.com/GoogleContainerTools/kpt-functions-sdk/go/fn"
	ipamv1alpha1 "github.com/nokia/k8s-ipam/apis/ipam/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func getIPAllocation(nfName string, epName types.NamespacedName, spec ipamv1alpha1.IPAllocationSpec) string {
	x := &ipamv1alpha1.IPAllocation{
		TypeMeta: metav1.TypeMeta{
			Kind:       "IPAllocation",
			APIVersion: "ipam.nephio.org/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      strings.Join([]string{nfName, epName.Name}, "-"),
			Namespace: epName.Namespace,
			Annotations: map[string]string{
				"config.kubernetes.io/local-config": "true",
			},
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

func MustGetValue(source *kyaml.RNode, fp string) string {
	fieldPath := utils.SmarterPathSplitter(fp, ".")
	foundValue, lookupErr := source.Pipe(&kyaml.PathGetter{Path: fieldPath})
	if lookupErr != nil {
		return ""
	}
	return strings.TrimSuffix(strings.ReplaceAll(foundValue.MustString(), `"`, ""), "\n")
}

func GetValue(source *kyaml.RNode, fp string) (string, error) {
	fieldPath := utils.SmarterPathSplitter(fp, ".")
	foundValue, lookupErr := source.Pipe(&kyaml.PathGetter{Path: fieldPath})
	if lookupErr != nil {
		return "", lookupErr
	}
	return strings.TrimSuffix(strings.ReplaceAll(foundValue.MustString(), `"`, ""), "\n"), nil
}

func GetPrefixKind(source *kyaml.RNode) string {
	return MustGetValue(source, "spec.kind")
}

func GetPrefixLength(source *kyaml.RNode) (int, error) {
	pl := MustGetValue(source, "spec.prefixLength")
	return strconv.Atoi(pl)
}

func GetIPAllocationSelectorMatchLabels(source *kyaml.RNode) (map[string]string, error) {
	labels := MustGetValue(source, "spec.selector.matchLabels")
	l := map[string]string{}
	if err := kyaml.Unmarshal([]byte(labels), l); err != nil {
		return nil, err
	}
	return l, nil
}

type IpamAllocation struct {
	Obj fn.KubeObject
}

func (r *IpamAllocation) GetSpec() (*ipamv1alpha1.IPAllocationSpec, error) {
	spec := r.Obj.GetMap("spec")
	selectorLabels, _, err := spec.NestedStringMap("selector", "matchLabels")
	if err != nil {
		return nil, err
	}

	ipAllocSpec := &ipamv1alpha1.IPAllocationSpec{
		PrefixKind:    spec.GetString("kind"),
		AddressFamily: spec.GetString("addressFamily"),
		Prefix:        spec.GetString("prefix"),
		PrefixLength:  uint8(spec.GetInt("prefixLength")),
		Selector: &metav1.LabelSelector{
			MatchLabels: selectorLabels,
		},
	}

	return ipAllocSpec, nil
}
