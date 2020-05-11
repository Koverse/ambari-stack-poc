from resource_management import *
from koverse_configuration import write_conf
from koverse_configuration import setup_conf

import sys
import time


class HelloWorldMaster(Script):
    
    
    def __init__(self):
        self.server_pid_file = "/var/run/hello-world.pid"

    def install(self, env):
        print 'Install Hello World.'

        # Install packages
        self.install_packages(env)

        print 'Installation complete.'

    def stop(self, env):
        
        # Stop Koverse server
        print 'Stop Hello World'
        Execute("systemctl stop hello-world.service")
        Execute("rm -f " + self.server_pid_file)       

    def start(self, env):
        import params
        env.set_params(params)
        self.configure(env)
        
        # Start your service
        print 'Start Hello World'
        Execute("systemctl start hello-world.service")
        # Sleep so Koverse Server has a chance to start
        time.sleep(10)
        # Capture PID for status
        Execute("echo `ps -ef | grep hello-world | grep -v grep | awk '{print $2}'` > " + self.server_pid_file)
        
    def status(self, env):
        print 'Status of the Hello World'
        
        check_process_status(self.server_pid_file)
        pass

if __name__ == "__main__":
    HelloWorldMaster().execute()
