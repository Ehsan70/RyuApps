<b>Goal</b>: This file contains the errors I have encountered durring the setup/run of the Ryu applicaitons.

<b>My Environment: </b> I am using SDN hub all-in-one Vm which has the following system characteristics: 
```
ubuntu@sdnhubvm:~/code/RyuApp[08:29]$ uname -a
Linux sdnhubvm 3.13.0-24-generic #47-Ubuntu SMP Fri May 2 23:30:00 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
```


## pkg_resources.VersionConflict
Probablley one of the packages doesn't match the desired version. 

#### Error Appearance
```shell
ubuntu@sdnhubvm:~/code/RyuApp[08:29]$ sudo ryu-manager ~/code/RyuApp/l2.py
Traceback (most recent call last):
  File "/usr/local/bin/ryu-manager", line 5, in <module>
    from pkg_resources import load_entry_point
  File "/usr/lib/python2.7/dist-packages/pkg_resources.py", line 2749, in <module>
    working_set = WorkingSet._build_master()
  File "/usr/lib/python2.7/dist-packages/pkg_resources.py", line 446, in _build_master
    return cls._build_from_requirements(__requires__)
  File "/usr/lib/python2.7/dist-packages/pkg_resources.py", line 459, in _build_from_requirements
    dists = ws.resolve(reqs, Environment())
  File "/usr/lib/python2.7/dist-packages/pkg_resources.py", line 632, in resolve
    raise VersionConflict(dist,req) # XXX put more info here
pkg_resources.VersionConflict: (netaddr 0.7.11 (/usr/local/lib/python2.7/dist-packages/netaddr-0.7.11-py2.7.egg), Requirement.parse('netaddr>=0.7.12'))
```

#### Solution 
I ran 
```shell
sudo pip install -U netaddr six pbr
```

#### References 
https://registry.hub.docker.com/u/osrg/ryu/ 




