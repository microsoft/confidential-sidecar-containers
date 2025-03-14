# Azure product naming and what example to use:

Today (February 2025) the production, (ie GA or "general availability") Confidential Containers solution in Azure is Confidential ACI (Azure Container Instances). It is available with two sorts of orchestration, direct ACI (create container groups one at a time and manage them yourself) and with AKS using "virtual nodes on Azure Container Instances".

There is a preview of AKS Confidential Pods which is based on the Kata scheme.

Some details of the ACI and Kata based solution are different. These include items such as how to invoke the az confcom policy tool and how various data is passed from the runtime into the container.

The examples in this repo are split between the ACI based and Kata based. They are named '''aci''' for ACI **AND** AKS with "virtual nodes on Azure Confidential Instances" and '''aks''' for the Kata based solution.

Eventually there will be specific "virtual nodes on Azure Container Instances" examples. In the meantime, use the regular ACI but replace the description of the containers in the ARM template with the similar description from your yaml file.

The documentaion for virtual nodes on Azure Confidential Instances is at https://learn.microsoft.com/en-us/azure/container-instances/container-instances-virtual-nodes and there is a github repo with instructions and Helm charts at https://github.com/microsoft/VirtualNodesOnAzureContainerInstances

