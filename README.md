#ambari-stack-poc

Ambari Stack for Hello World

-----------------------

To package the stack, copy KDP directory to /var/lib/ambari-server/resources/stacks/ to an ambari server without a 
cluster currently deployed

-----------------------

Restart the Ambari Server to have the service activated:

`sudo ambari-server restart`

-----------------------

Open ambari and create a cluster
Select KDP-1.1

-----------------------

After cluster is deployed, add the Hello World service (currently this is failing)

