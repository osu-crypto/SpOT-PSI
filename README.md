### Windows

First clone and build libOTe which should share the same parent directory. Then clone this library and open the solution in Visaul Studio.

### Linux

```
git clone --recursive git@github.com:nitrieu/SpOT-PSI_impl.git
```

###### build libOTe
```
cd SpOT-PSI_impl/libOTe/cryptoTools/thirdparty/linux
bash all.get
cd ../../..
cmake  -G "Unix Makefiles"
make
```

###### build extra ntl library 
```
cd SpOT-PSI_impl/thirdparty/linux/
bash ntl.get
```

###### compile
```
cd SpOT-PSI_impl
cmake .
make 
```
###### run (folder SpOT-PSI_impl)
```
./bin/frontend.exe -r 0 & ./bin/frontend.exe -r 1
```

