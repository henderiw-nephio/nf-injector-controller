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

package upf

import (
	"fmt"
	"strings"

	"github.com/GoogleContainerTools/kpt-functions-sdk/go/fn"
	nfv1alpha1 "github.com/nephio-project/nephio-pocs/nephio-5gc-controller/apis/nf/v1alpha1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/cli-runtime/pkg/printers"
	"sigs.k8s.io/kustomize/kyaml/utils"
	kyaml "sigs.k8s.io/kustomize/kyaml/yaml"
)

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

func GetEndpoint(epName string, source *kyaml.RNode) (*nfv1alpha1.Endpoint, error) {
	networkInstance, err := GetValue(source, fmt.Sprintf("spec.upfs.0.upf.%s.0.networkInstance", epName))
	if err != nil {
		return nil, err
	}
	networkName, err := GetValue(source, fmt.Sprintf("spec.upfs.0.upf..%s.0.networkName", epName))
	if err != nil {
		return nil, err
	}

	return &nfv1alpha1.Endpoint{
		NetworkInstance: &networkInstance,
		NetworkName:     &networkName,
	}, nil
}

func GetN6Endpoint(epName string, source *kyaml.RNode) (*nfv1alpha1.N6Endpoint, error) {
	networkInstance, err := GetValue(source, fmt.Sprintf("spec.upfs.0.upf.%s.0.endpoint.networkInstance", epName))
	if err != nil {
		return nil, err
	}
	networkName, err := GetValue(source, fmt.Sprintf("spec.upfs.0.upf.%s.0.endpoint.networkName", epName))
	if err != nil {
		return nil, err
	}

	poolNetworkInstance, err := GetValue(source, fmt.Sprintf("spec.upfs.0.upf.%s.0.uePool.networkInstance", epName))
	if err != nil {
		return nil, err
	}

	poolNetworkName, err := GetValue(source, fmt.Sprintf("spec.upfs.0.upf.%s.0.uePool.networkName", epName))
	if err != nil {
		return nil, err
	}
	poolPrefixSize, err := GetValue(source, fmt.Sprintf("spec.upfs.0.upf.%s.0.uePool.prefixSize", epName))
	if err != nil {
		return nil, err
	}
	poolPrefixSize = strings.ReplaceAll(poolPrefixSize, "/", "")

	return &nfv1alpha1.N6Endpoint{
		Endpoint: nfv1alpha1.Endpoint{
			NetworkInstance: &networkInstance,
			NetworkName:     &networkName,
		},
		UEPool: nfv1alpha1.Pool{
			NetworkInstance: &poolNetworkInstance,
			NetworkName:     &poolNetworkName,
			PrefixSize:      &poolPrefixSize,
		},
	}, nil
}

func GetDnn(source *kyaml.RNode) string {
	return MustGetValue(source, "spec.upfs.0.upf.n6.0.dnn")
}

func GetCapacity(source *kyaml.RNode) nfv1alpha1.UPFCapacity {
	uplinkThroughput := MustGetValue(source, "spec.upfs.0.upf.capacity.uplinkThroughput")
	downlinkThroughput := MustGetValue(source, "spec.upfs.0.upf.capacity.downlinkThroughput")

	uplinkThroughput = strings.ReplaceAll(uplinkThroughput, `"`, "")
	downlinkThroughput = strings.ReplaceAll(downlinkThroughput, `"`, "")
	return nfv1alpha1.UPFCapacity{
		UplinkThroughput:   resource.MustParse(uplinkThroughput),
		DownlinkThroughput: resource.MustParse(downlinkThroughput),
	}
}

func GetRegion(source *kyaml.RNode) (string, error) {
	labels := MustGetValue(source, "spec.upfs.0.selector.matchLabels")
	l := map[string]string{}
	if err := kyaml.Unmarshal([]byte(labels), l); err != nil {
		return "", err
	}
	return l["nephio.org/region"], nil
}

func GetDummyInterface(n string) nfv1alpha1.InterfaceConfig {
	return nfv1alpha1.InterfaceConfig{
		Name:       n,
		IPs:        []string{""},
		GatewayIPs: []string{""},
	}
}

func GetDummyInterfaces(n string) []nfv1alpha1.InterfaceConfig {
	i := make([]nfv1alpha1.InterfaceConfig, 0)
	return append(i, GetDummyInterface(n))
}

func GetN6DummyInterfaces(n, dnn string) []nfv1alpha1.N6InterfaceConfig {
	return []nfv1alpha1.N6InterfaceConfig{
		{
			Interface: GetDummyInterface(n),
			DNN:       "",
			UEIPPool:  "",
		},
	}
}

func BuildUPFDeploymentSpec(endponts map[string]*nfv1alpha1.Endpoint, dnn string, capacity nfv1alpha1.UPFCapacity) nfv1alpha1.UPFDeploymentSpec {
	spec := nfv1alpha1.UPFDeploymentSpec{
		Capacity: capacity,
	}
	for epName, ep := range endponts {
		if ep != nil {
			switch epName {
			case "n3":
				spec.N3Interfaces = GetDummyInterfaces(epName)
			case "n4":
				spec.N4Interfaces = GetDummyInterfaces(epName)
			case "n6":
				spec.N6Interfaces = GetN6DummyInterfaces(epName, dnn)
			case "n9":
				spec.N9Interfaces = GetDummyInterfaces(epName)
			}
		}
	}
	return spec
}

func getUPFDeployment(nsName types.NamespacedName, spec nfv1alpha1.UPFDeploymentSpec) string {
	x := &nfv1alpha1.UPFDeployment{
		TypeMeta: metav1.TypeMeta{
			Kind:       "UPFDeployment",
			APIVersion: "nf.nephio.org/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      nsName.Name,
			Namespace: nsName.Namespace,
		},
		Spec: spec,
	}

	b := new(strings.Builder)
	p := printers.YAMLPrinter{}
	p.PrintObj(x, b)
	return b.String()
}

func BuildUPFDeploymentFn(nsName types.NamespacedName, spec nfv1alpha1.UPFDeploymentSpec) (*fn.KubeObject, error) {
	x := getUPFDeployment(nsName, spec)
	return fn.ParseKubeObject([]byte(x))
}

func BuildUPFDeployment(nsName types.NamespacedName, spec nfv1alpha1.UPFDeploymentSpec) (*kyaml.RNode, error) {
	x := getUPFDeployment(nsName, spec)
	return kyaml.Parse(x)
}
