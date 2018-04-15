### Windows

```
git clone --recursive git@github.com:nitrieu/SpOT-PSI_impl.git
```


...........

##### change ntl code
```
   struct MatPrime_crt_helper_deleter_policy {
      static void deleter(MatPrime_crt_helper *p) { MatPrime_crt_helper_deleter(p); }
   };
```
to
```
   struct MatPrime_crt_helper_deleter_policy {
      static void deleter(MatPrime_crt_helper *p) {; }
   };
```

In lip.h, change _ntl_general_rem_one_struct to be a struct. 

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

