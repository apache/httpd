# Get Apache on IBM Cloud

You should have an IBM Cloud account, otherwise you can [register here].
At the end of the tutorial you will have a cluster with an Apache up and runnning.

1. We will provision a new Kubernetes Cluster for you if, you already have one skip to step **2**
2. We will deploy  the IBM Cloud Block Storage plug-in, if already have it skip to step **3**
3. Apache deployment

## Step 1 provision Kubernetes Cluster

* Click the **Catalog** button on the top 
* Select **Service** from the catalog
* Search for **Kubernetes Service** and click on it
![Kubernetes](/docs/INSTALL/kubernetes-select.png)
* You are now at the Kubernetes deployment page, you need to specify some details about the cluster 
* Choose a plan **standard** or **free**, the free plan only has one worker node and no subnet, to provision a standard cluster, you will need to upgrade you account to Pay-As-You-Go 
  * To upgrade to a Pay-As-You-Go account, complete the following steps:

  * In the console, go to Manage > Account.
  * Select Account settings, and click Add credit card.
  * Enter your payment information, click Next, and submit your information
* Choose **classic** or **VPC**, read the [docs] and choose the most suitable type for yourself 
 ![VPC](/docs/INSTALL/infra-select.png)
* Now choose your location settings, for more information please visit [Locations]
  * Choose **Geography** (continent)
![continent](/docs/INSTALL/location-geo.png)
  * Choose **Single** or **Multizone**, in single zone your data is only kept in on datacenter, on the other hand with Multizone it is distributed to multiple zones, thus  safer in an unforseen zone failure 
![avail](/docs/INSTALL/location-avail.png)
  * Choose a **Worker Zone** if using Single zones or **Metro** if Multizone
 ![worker](/docs/INSTALL/location-worker.png) 
    * If you wish to use Multizone please set up your account with [VRF] or [enable Vlan spanning]
    * If at your current location selection, there is no available Virtual LAN, a new Vlan will be created for you 
 
* Choose a **Worker node setup** or use the preselected one, set **Worker node amount per zone**
![worker-pool](/docs/INSTALL/worker-pool.png)
* Choose **Master Service Endpoint**,  In VRF-enabled accounts, you can choose private-only to make your master accessible on the private network or via VPN tunnel. Choose public-only to make your master publicly accessible. When you have a VRF-enabled account, your cluster is set up by default to use both private and public endpoints. For more information visit [endpoints].
![endpoints](/docs/INSTALL/endpoints.png)
* Give cluster a **name**

![name-new](/docs/INSTALL/name-new.png)
* Give desired **tags** to your cluster, for more information visit [tags]

![tags-new]/docs/INSTALL(/tasg-new.png)
* Click **create**
![create-new](/docs/INSTALL/create-new.png)

* Wait for you cluster to be provisioned 
![cluster-prepare](/docs/INSTALL/cluster-prepare.png)
* Your cluster is ready for usage 

![cluster-ready](/docs/INSTALL/cluster-done.png)

## Step 2 deploy IBM Cloud Block Storage plug-in
The Block Storage plug-in is a persistent, high-performance iSCSI storage that you can add to your apps by using Kubernetes Persistent Volumes (PVs).
 
* Click the **Catalog** button on the top 
* Select **Software** from the catalog
* Search for **IBM Cloud Block Storage plug-in** and click on it
![Block](/docs/INSTALL/block-search.png)

* On the application page Click in the _dot_ next to the cluster, you wish to use
* Click on  **Enter or Select Namespace** and choose the default Namespace or use a custom one (if you get error please wait 30 minutes for the cluster to finalize)
![block-c](/docs/INSTALL/block-cluster.png)
* Give a **name** to this workspace 
* Click **install** and wait for the deployment
![block-create](/docs/INSTALL/block-storage-create.png)
 

## Step 3 deploy Apache
  
We will deploy  Apache on our cluster 
  
* Click the **Catalog** button on the top 
* Select **Software** from the catalog
* Search for **Apache** and click on it
![Apache](/docs/INSTALL/apache-select.png)


* On the application page Click in the _dot_ next to the cluster, you wish to use
![Cluster](/docs/INSTALL/cluster-select.png)
* Click on  **Enter or Select Namespace** and choose the default Namespace or use a custom one 
![Namespace](/docs/INSTALL/namespace.png)
* Give a unique **name** to workspace, which you can easily recognize
![Name](/docs/INSTALL/name.png)
* Give **tags** to your apache workspace, for more information visit [tags]

![apache-tags](/docs/INSTALL/apache-tags.png)

* Click on **Parameters with default values**, You can set deployment values or use the default ones

![def-val](/docs/INSTALL/deploy-values.png)

* After finishing everything, **tick** the box next to the agreements and click **install**

![Install](/docs/INSTALL/install.png)

* The apache workspace will start installing, wait a couple of minutes 

![apache-install](/docs/INSTALL/apache-loading.jpg)

* You apache workspace has been successfully deployed

![apache-finsihed](/docs/INSTALL/apache-finished.jpg)

## Verify Apache installation

* Go to [Resources] in your browser 
* Click on **Clusters**
* Click on your Cluster
![Resourcelect](/docs/INSTALL/resource-select.png)

* Now you are at you clusters overview, here Click on **Actions** and **Web terminal** from the dropdown menu


![Actions](/docs/INSTALL/cluster-main.png)

* Click **install** - wait couple of minutes 

![terminal-install](/docs/INSTALL/terminal-install.jpg)

* Click on **Actions**
* Click **Web terminal** --> a terminal will open up

* **Type** in the terminal, please change NAMESPACE to the namespace you choose at the deployment setup:

 ```sh
$ kubectl get ns
```
![get-ns](/docs/INSTALL/get-ns.jpg)


 ```sh
$ kubectl get pod -n NAMESPACE -o wide 
```
![get-pod](/docs/INSTALL/get-pod.jpg)


 ```sh
$ kubectl get service -n NAMESPACE
```
![get-service](/docs/INSTALL/get-service.jpg)


* Running Apache service will be visible 
* Copy the **External ip**, you can access the website on this IP
* Paste it into your browser
* Apache welcome message will be visible

![works](/docs/INSTALL/apache-works.png)

You successfully deployed an Apache webserver on IBM Cloud! 



 
   [IBM Cloud]: <http://cloud.ibm.com>
   [Resources]: <http://cloud.ibm.com/resources>
   [Register Here]: <http://cloud.ibm.com/registration>
   [docs]: <https://cloud.ibm.com/docs/containers?topic=containers-infrastructure_providers>
   [Locations]: <https://cloud.ibm.com/docs/containers?topic=containers-regions-and-zones#zones>
   [VRF]: <https://cloud.ibm.com/docs/dl?topic=dl-overview-of-virtual-routing-and-forwarding-vrf-on-ibm-cloud>
   [enable Vlan spanning]: <https://cloud.ibm.com/docs/vlans?topic=vlans-vlan-spanning#vlan-spanning>
   [endpoints]: <https://cloud.ibm.com/docs/account?topic=account-service-endpoints-overview>
   [tags]: <https://cloud.ibm.com/docs/account?topic=account-tag>
