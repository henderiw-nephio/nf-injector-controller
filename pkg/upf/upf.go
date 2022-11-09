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

	nfv1alpha1 "github.com/nephio-project/nephio-pocs/nephio-5gc-controller/apis/nf/v1alpha1"
	"sigs.k8s.io/kustomize/kyaml/utils"
	kyaml "sigs.k8s.io/kustomize/kyaml/yaml"
)

func GetValue(source *kyaml.RNode, fp string) (string, error) {
	fieldPath := utils.SmarterPathSplitter(fp, ".")
	foundValue, lookupErr := source.Pipe(&kyaml.PathGetter{Path: fieldPath})
	if lookupErr != nil {
		return "", lookupErr
	}
	return strings.TrimSuffix(foundValue.MustString(), "\n"), nil
}

func GetEndpoint(epName string, source *kyaml.RNode) (*nfv1alpha1.Endpoint, error) {
	networkInstance, err := GetValue(source, fmt.Sprintf("spec.%s.0.networkInstance", epName))
	if err != nil {
		return nil, err
	}
	networkName, err := GetValue(source, fmt.Sprintf("spec.%s.0.networkName", epName))
	if err != nil {
		return nil, err
	}

	return &nfv1alpha1.Endpoint{
		NetworkInstance: &networkInstance,
		NetworkName:     &networkName,
	}, nil
}

func GetN6Endpoint(epName string, source *kyaml.RNode) (*nfv1alpha1.N6Endpoint, error) {
	networkInstance, err := GetValue(source, fmt.Sprintf("spec.%s.endpoint.networkInstance", epName))
	if err != nil {
		return nil, err
	}
	networkName, err := GetValue(source, fmt.Sprintf("spec.%s.endpoint.networkName", epName))
	if err != nil {
		return nil, err
	}

	poolNetworkInstance, err := GetValue(source, fmt.Sprintf("spec.%s.pool.0.networkInstance", epName))
	if err != nil {
		return nil, err
	}
	poolNetworkName, err := GetValue(source, fmt.Sprintf("spec.%s.pool.0.networkName", epName))
	if err != nil {
		return nil, err
	}
	poolPrefixSize, err := GetValue(source, fmt.Sprintf("spec.%s.pool.0.prefixSize", epName))
	if err != nil {
		return nil, err
	}

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
