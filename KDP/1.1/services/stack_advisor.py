#!/usr/bin/env ambari-python-wrap
"""
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import re
import os
import sys
import socket

from math import ceil, floor

from resource_management.libraries.functions.mounted_dirs_helper import get_mounts_with_multiple_data_dirs

from stack_advisor import DefaultStackAdvisor


class KDP10StackAdvisor(DefaultStackAdvisor):

  def __init__(self):
    super(KDP10StackAdvisor, self).__init__()
    self.initialize_logger("KDP10StackAdvisor")

  def getComponentLayoutValidations(self, services, hosts):
    """Returns array of Validation objects about issues with hostnames components assigned to"""
    items = super(KDP10StackAdvisor, self).getComponentLayoutValidations(services, hosts)

    # Validating NAMENODE and SECONDARY_NAMENODE are on different hosts if possible
    # Use a set for fast lookup
    hostsSet =  set(super(KDP10StackAdvisor, self).getActiveHosts([host["Hosts"] for host in hosts["items"]]))  #[host["Hosts"]["host_name"] for host in hosts["items"]]
    hostsCount = len(hostsSet)

    componentsListList = [service["components"] for service in services["services"]]
    componentsList = [item for sublist in componentsListList for item in sublist]
    nameNodeHosts = [component["StackServiceComponents"]["hostnames"] for component in componentsList if component["StackServiceComponents"]["component_name"] == "NAMENODE"]
    secondaryNameNodeHosts = [component["StackServiceComponents"]["hostnames"] for component in componentsList if component["StackServiceComponents"]["component_name"] == "SECONDARY_NAMENODE"]

    # Validating cardinality
    for component in componentsList:
      if component["StackServiceComponents"]["cardinality"] is not None:
         componentName = component["StackServiceComponents"]["component_name"]
         componentDisplayName = component["StackServiceComponents"]["display_name"]
         componentHosts = []
         if component["StackServiceComponents"]["hostnames"] is not None:
           componentHosts = [componentHost for componentHost in component["StackServiceComponents"]["hostnames"] if componentHost in hostsSet]
         componentHostsCount = len(componentHosts)
         cardinality = str(component["StackServiceComponents"]["cardinality"])
         # cardinality types: null, 1+, 1-2, 1, ALL
         message = None
         if "+" in cardinality:
           hostsMin = int(cardinality[:-1])
           if componentHostsCount < hostsMin:
             message = "At least {0} {1} components should be installed in cluster.".format(hostsMin, componentDisplayName)
         elif "-" in cardinality:
           nums = cardinality.split("-")
           hostsMin = int(nums[0])
           hostsMax = int(nums[1])
           if componentHostsCount > hostsMax or componentHostsCount < hostsMin:
             message = "Between {0} and {1} {2} components should be installed in cluster.".format(hostsMin, hostsMax, componentDisplayName)
         elif "ALL" == cardinality:
           if componentHostsCount != hostsCount:
             message = "{0} component should be installed on all hosts in cluster.".format(componentDisplayName)
         else:
           if componentHostsCount != int(cardinality):
             message = "Exactly {0} {1} components should be installed in cluster.".format(int(cardinality), componentDisplayName)

         if message is not None:
           items.append({"type": 'host-component', "level": 'ERROR', "message": message, "component-name": componentName})

    # Validating host-usage
    usedHostsListList = [component["StackServiceComponents"]["hostnames"] for component in componentsList if not self.isComponentNotValuable(component)]
    usedHostsList = [item for sublist in usedHostsListList for item in sublist]
    nonUsedHostsList = [item for item in hostsSet if item not in usedHostsList]
    for host in nonUsedHostsList:
      items.append( { "type": 'host-component', "level": 'ERROR', "message": 'Host is not used', "host": str(host) } )

    return items

  def getServiceConfigurationRecommenderDict(self):
    return {
      "HELLO_WORLD": self.recommendHelloWorldConfigurations
    }

  def recommendHelloWorldConfigurations(self, configurations, clusterData, services, hosts):
    return []

  def getAmbariUser(self, services):
    ambari_user = services['ambari-server-properties']['ambari-server.user']
    if "cluster-env" in services["configurations"] \
          and "ambari_principal_name" in services["configurations"]["cluster-env"]["properties"] \
                and "security_enabled" in services["configurations"]["cluster-env"]["properties"] \
                    and services["configurations"]["cluster-env"]["properties"]["security_enabled"].lower() == "true":
      ambari_user = services["configurations"]["cluster-env"]["properties"]["ambari_principal_name"]
      ambari_user = ambari_user.split('@')[0]
    return ambari_user

  def getOldAmbariUser(self, services):
    ambari_user = None
    if "cluster-env" in services["configurations"]:
      if "security_enabled" in services["configurations"]["cluster-env"]["properties"] \
              and services["configurations"]["cluster-env"]["properties"]["security_enabled"].lower() == "true":
         ambari_user = services['ambari-server-properties']['ambari-server.user']
      elif "ambari_principal_name" in services["configurations"]["cluster-env"]["properties"]:
         ambari_user = services["configurations"]["cluster-env"]["properties"]["ambari_principal_name"]
         ambari_user = ambari_user.split('@')[0]
    return ambari_user

  def getHostNamesWithComponent(self, serviceName, componentName, services):
    """
    Returns the list of hostnames on which service component is installed
    """
    if services is not None and serviceName in [service["StackServices"]["service_name"] for service in services["services"]]:
      service = [serviceEntry for serviceEntry in services["services"] if serviceEntry["StackServices"]["service_name"] == serviceName][0]
      components = [componentEntry for componentEntry in service["components"] if componentEntry["StackServiceComponents"]["component_name"] == componentName]
      if (len(components) > 0 and len(components[0]["StackServiceComponents"]["hostnames"]) > 0):
        componentHostnames = components[0]["StackServiceComponents"]["hostnames"]
        return componentHostnames
    return []

  def getHostsWithComponent(self, serviceName, componentName, services, hosts):
    if services is not None and hosts is not None and serviceName in [service["StackServices"]["service_name"] for service in services["services"]]:
      service = [serviceEntry for serviceEntry in services["services"] if serviceEntry["StackServices"]["service_name"] == serviceName][0]
      components = [componentEntry for componentEntry in service["components"] if componentEntry["StackServiceComponents"]["component_name"] == componentName]
      if (len(components) > 0 and len(components[0]["StackServiceComponents"]["hostnames"]) > 0):
        componentHostnames = components[0]["StackServiceComponents"]["hostnames"]
        componentHosts = [host for host in hosts["items"] if host["Hosts"]["host_name"] in componentHostnames]
        return componentHosts
    return []

  def getHostWithComponent(self, serviceName, componentName, services, hosts):
    componentHosts = self.getHostsWithComponent(serviceName, componentName, services, hosts)
    if (len(componentHosts) > 0):
      return componentHosts[0]
    return None

  def getHostComponentsByCategories(self, hostname, categories, services, hosts):
    components = []
    if services is not None and hosts is not None:
      for service in services["services"]:
          components.extend([componentEntry for componentEntry in service["components"]
                              if componentEntry["StackServiceComponents"]["component_category"] in categories
                              and hostname in componentEntry["StackServiceComponents"]["hostnames"]])
    return components

  def getServiceConfigurationValidators(self):
    return {
      "HELLO_WORLD": { "hello-world-config": self.validateHelloWorldConfigurations }
    }

  def validateMinMax(self, items, recommendedDefaults, configurations):

    # required for casting to the proper numeric type before comparison
    def convertToNumber(number):
      try:
        return int(number)
      except ValueError:
        return float(number)

    for configName in configurations:
      validationItems = []
      if configName in recommendedDefaults and "property_attributes" in recommendedDefaults[configName]:
        for propertyName in recommendedDefaults[configName]["property_attributes"]:
          if propertyName in configurations[configName]["properties"]:
            if "maximum" in recommendedDefaults[configName]["property_attributes"][propertyName] and \
                propertyName in recommendedDefaults[configName]["properties"]:
              userValue = convertToNumber(configurations[configName]["properties"][propertyName])
              maxValue = convertToNumber(recommendedDefaults[configName]["property_attributes"][propertyName]["maximum"])
              if userValue > maxValue:
                validationItems.extend([{"config-name": propertyName, "item": self.getWarnItem("Value is greater than the recommended maximum of {0} ".format(maxValue))}])
            if "minimum" in recommendedDefaults[configName]["property_attributes"][propertyName] and \
                    propertyName in recommendedDefaults[configName]["properties"]:
              userValue = convertToNumber(configurations[configName]["properties"][propertyName])
              minValue = convertToNumber(recommendedDefaults[configName]["property_attributes"][propertyName]["minimum"])
              if userValue < minValue:
                validationItems.extend([{"config-name": propertyName, "item": self.getWarnItem("Value is less than the recommended minimum of {0} ".format(minValue))}])
      items.extend(self.toConfigurationValidationProblems(validationItems, configName))
    pass

  def validateHelloWorldConfigurations(self, properties, recommendedDefaults, configurations, services, hosts):
    validationItems = []

    return self.toConfigurationValidationProblems(validationItems, "hello-world-config")

  def get_system_min_uid(self):
    login_defs = '/etc/login.defs'
    uid_min_tag = 'UID_MIN'
    comment_tag = '#'
    uid_min = uid_default = '1000'
    uid = None

    if os.path.exists(login_defs):
      with open(login_defs, 'r') as f:
        data = f.read().split('\n')
        # look for uid_min_tag in file
        uid = filter(lambda x: uid_min_tag in x, data)
        # filter all lines, where uid_min_tag was found in comments
        uid = filter(lambda x: x.find(comment_tag) > x.find(uid_min_tag) or x.find(comment_tag) == -1, uid)

      if uid is not None and len(uid) > 0:
        uid = uid[0]
        comment = uid.find(comment_tag)
        tag = uid.find(uid_min_tag)
        if comment == -1:
          uid_tag = tag + len(uid_min_tag)
          uid_min = uid[uid_tag:].strip()
        elif comment > tag:
          uid_tag = tag + len(uid_min_tag)
          uid_min = uid[uid_tag:comment].strip()

    # check result for value
    try:
      int(uid_min)
    except ValueError:
      return uid_default

    return uid_min

  def mergeValidators(self, parentValidators, childValidators):
    for service, configsDict in childValidators.iteritems():
      if service not in parentValidators:
        parentValidators[service] = {}
      parentValidators[service].update(configsDict)

  def checkSiteProperties(self, siteProperties, *propertyNames):
    """
    Check if properties defined in site properties.
    :param siteProperties: config properties dict
    :param *propertyNames: property names to validate
    :returns: True if all properties defined, in other cases returns False
    """
    if siteProperties is None:
      return False
    for name in propertyNames:
      if not (name in siteProperties):
        return False
    return True

  """
  Returns the dictionary of configs for 'capacity-scheduler'.
  """
  def getCapacitySchedulerProperties(self, services):
    capacity_scheduler_properties = dict()
    received_as_key_value_pair = True
    if "capacity-scheduler" in services['configurations']:
      if "capacity-scheduler" in services['configurations']["capacity-scheduler"]["properties"]:
        cap_sched_props_as_str = services['configurations']["capacity-scheduler"]["properties"]["capacity-scheduler"]
        if cap_sched_props_as_str:
          cap_sched_props_as_str = str(cap_sched_props_as_str).split('\n')
          if len(cap_sched_props_as_str) > 0 and cap_sched_props_as_str[0] != 'null':
            # Received confgs as one "\n" separated string
            for property in cap_sched_props_as_str:
              key, sep, value = property.partition("=")
              capacity_scheduler_properties[key] = value
            self.logger.info("'capacity-scheduler' configs is passed-in as a single '\\n' separated string. "
                        "count(services['configurations']['capacity-scheduler']['properties']['capacity-scheduler']) = "
                        "{0}".format(len(capacity_scheduler_properties)))
            received_as_key_value_pair = False
          else:
            self.logger.info("Passed-in services['configurations']['capacity-scheduler']['properties']['capacity-scheduler'] is 'null'.")
        else:
          self.logger.info("'capacity-schdeuler' configs not passed-in as single '\\n' string in "
                      "services['configurations']['capacity-scheduler']['properties']['capacity-scheduler'].")
      if not capacity_scheduler_properties:
        # Received configs as a dictionary (Generally on 1st invocation).
        capacity_scheduler_properties = services['configurations']["capacity-scheduler"]["properties"]
        self.logger.info("'capacity-scheduler' configs is passed-in as a dictionary. "
                    "count(services['configurations']['capacity-scheduler']['properties']) = {0}".format(len(capacity_scheduler_properties)))
    else:
      self.logger.error("Couldn't retrieve 'capacity-scheduler' from services.")

    self.logger.info("Retrieved 'capacity-scheduler' received as dictionary : '{0}'. configs : {1}" \
                .format(received_as_key_value_pair, capacity_scheduler_properties.items()))
    return capacity_scheduler_properties, received_as_key_value_pair

  def get_service_component_meta(self, service, component, services):
    """
    Function retrieve service component meta information as dict from services.json
    If no service or component found, would be returned empty dict

    Return value example:
        "advertise_version" : true,
        "bulk_commands_display_name" : "",
        "bulk_commands_master_component_name" : "",
        "cardinality" : "1+",
        "component_category" : "CLIENT",
        "component_name" : "HBASE_CLIENT",
        "custom_commands" : [ ],
        "decommission_allowed" : false,
        "display_name" : "HBase Client",
        "has_bulk_commands_definition" : false,
        "is_client" : true,
        "is_master" : false,
        "reassign_allowed" : false,
        "recovery_enabled" : false,
        "service_name" : "HBASE",
        "stack_name" : "HDP",
        "stack_version" : "2.5",
        "hostnames" : [ "host1", "host2" ]

    :type service str
    :type component str
    :type services dict
    :rtype dict
    """
    __stack_services = "StackServices"
    __stack_service_components = "StackServiceComponents"

    if not services:
      return {}

    service_meta = [item for item in services["services"] if item[__stack_services]["service_name"] == service]
    if len(service_meta) == 0:
      return {}

    service_meta = service_meta[0]
    component_meta = [item for item in service_meta["components"] if item[__stack_service_components]["component_name"] == component]

    if len(component_meta) == 0:
      return {}

    return component_meta[0][__stack_service_components]

  def is_secured_cluster(self, services):
    """
    Detects if cluster is secured or not
    :type services dict
    :rtype bool
    """
    return services and "cluster-env" in services["configurations"] and\
           "security_enabled" in services["configurations"]["cluster-env"]["properties"] and\
           services["configurations"]["cluster-env"]["properties"]["security_enabled"].lower() == "true"

  def get_services_list(self, services):
    """
    Returns available services as list

    :type services dict
    :rtype list
    """
    if not services:
      return []

    return [service["StackServices"]["service_name"] for service in services["services"]]

  def get_components_list(self, service, services):
    """
    Return list of components for specific service
    :type service str
    :type services dict
    :rtype list
    """
    __stack_services = "StackServices"
    __stack_service_components = "StackServiceComponents"

    if not services:
      return []

    service_meta = [item for item in services["services"] if item[__stack_services]["service_name"] == service]
    if len(service_meta) == 0:
      return []

    service_meta = service_meta[0]
    return [item[__stack_service_components]["component_name"] for item in service_meta["components"]]


def getOldValue(self, services, configType, propertyName):
  if services:
    if 'changed-configurations' in services.keys():
      changedConfigs = services["changed-configurations"]
      for changedConfig in changedConfigs:
        if changedConfig["type"] == configType and changedConfig["name"]== propertyName and "old_value" in changedConfig:
          return changedConfig["old_value"]
  return None

# Validation helper methods
def getSiteProperties(configurations, siteName):
  siteConfig = configurations.get(siteName)
  if siteConfig is None:
    return None
  return siteConfig.get("properties")

def getServicesSiteProperties(services, siteName):
  configurations = services.get("configurations")
  if not configurations:
    return None
  siteConfig = configurations.get(siteName)
  if siteConfig is None:
    return None
  return siteConfig.get("properties")

def to_number(s):
  try:
    return int(re.sub("\D", "", s))
  except ValueError:
    return None

def checkXmxValueFormat(value):
  p = re.compile('-Xmx(\d+)(b|k|m|g|p|t|B|K|M|G|P|T)?')
  matches = p.findall(value)
  return len(matches) == 1

def getXmxSize(value):
  p = re.compile("-Xmx(\d+)(.?)")
  result = p.findall(value)[0]
  if len(result) > 1:
    # result[1] - is a space or size formatter (b|k|m|g etc)
    return result[0] + result[1].lower()
  return result[0]

def formatXmxSizeToBytes(value):
  value = value.lower()
  if len(value) == 0:
    return 0
  modifier = value[-1]

  if modifier == ' ' or modifier in "0123456789":
    modifier = 'b'
  m = {
    modifier == 'b': 1,
    modifier == 'k': 1024,
    modifier == 'm': 1024 * 1024,
    modifier == 'g': 1024 * 1024 * 1024,
    modifier == 't': 1024 * 1024 * 1024 * 1024,
    modifier == 'p': 1024 * 1024 * 1024 * 1024 * 1024
    }[1]
  return to_number(value) * m

def getPort(address):
  """
  Extracts port from the address like 0.0.0.0:1019
  """
  if address is None:
    return None
  m = re.search(r'(?:http(?:s)?://)?([\w\d.]*):(\d{1,5})', address)
  if m is not None:
    return int(m.group(2))
  else:
    return None

def isSecurePort(port):
  """
  Returns True if port is root-owned at *nix systems
  """
  if port is not None:
    return port < 1024
  else:
    return False

def getMountPointForDir(dir, mountPoints):
  """
  :param dir: Directory to check, even if it doesn't exist.
  :return: Returns the closest mount point as a string for the directory.
  if the "dir" variable is None, will return None.
  If the directory does not exist, will return "/".
  """
  bestMountFound = None
  if dir:
    dir = re.sub("^file://", "", dir, count=1).strip().lower()

    # If the path is "/hadoop/hdfs/data", then possible matches for mounts could be
    # "/", "/hadoop/hdfs", and "/hadoop/hdfs/data".
    # So take the one with the greatest number of segments.
    for mountPoint in mountPoints:
      # Ensure that the mount path and the dir path ends with "/"
      # The mount point "/hadoop" should not match with the path "/hadoop1"
      if os.path.join(dir, "").startswith(os.path.join(mountPoint, "")):
        if bestMountFound is None:
          bestMountFound = mountPoint
        elif os.path.join(bestMountFound, "").count(os.path.sep) < os.path.join(mountPoint, "").count(os.path.sep):
          bestMountFound = mountPoint

  return bestMountFound

def getMemorySizeRequired(components, configurations):
  totalMemoryRequired = 512*1024*1024 # 512Mb for OS needs
  for component in components:
    if component in getHeapsizeProperties().keys():
      heapSizeProperties = getHeapsizeProperties()[component]
      for heapSizeProperty in heapSizeProperties:
        try:
          properties = configurations[heapSizeProperty["config-name"]]["properties"]
          heapsize = properties[heapSizeProperty["property"]]
        except KeyError:
          heapsize = heapSizeProperty["default"]

        # Assume Mb if no modifier
        if len(heapsize) > 1 and heapsize[-1] in '0123456789':
          heapsize = str(heapsize) + "m"

        totalMemoryRequired += formatXmxSizeToBytes(heapsize)

  return totalMemoryRequired

def round_to_n(mem_size, n=128):
  return int(round(mem_size / float(n))) * int(n)
