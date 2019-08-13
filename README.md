# Sparse OT Extension & PSI
This is the implementation of our [CRYPTO 2019](http://dl.acm.org/citation.cfm?id=2978381)  paper: **SpOT-Light: Lightweight Private Set Intersection from Sparse OT Extension**[[ePrint](https://eprint.iacr.org/2019/634.pdf)]. 

Evaluating on a single server (`2 36-cores Intel Xeon CPU E5-2699 v3 @ 2.30GHz and 256GB of RAM`) with a single thread per party, each party has `2^20` items, our `spot-low` protocol requires  `270` seconds and `63.1` MB , and our `spot-fast` protocol requires  `25.6` seconds and `76.4` MB. 

## Installations
### Clone project
```
git clone --recursive git@github.com:osu-crypto/SpOT-PSI.git
```

### Required libraries
 C++ compiler with C++14 support. There are several library dependencies including [`Boost`](https://sourceforge.net/projects/boost/), [`Miracl`](https://github.com/miracl/MIRACL), [`NTL`](http://www.shoup.net/ntl/) with GMP, and [`libOTe`](https://github.com/osu-crypto/libOTe). For `libOTe`, it requires CPU supporting `PCLMUL`, `AES-NI`, and `SSE4.1`. Optional: `nasm` for improved SHA1 performance.   Our code has been tested on both Windows (Microsoft Visual Studio) and Linux. To install the required libraries: 
  * For building boost, miracl and libOTe, please follow the more instructions at [`libOTe`](https://github.com/osu-crypto/libOTe). A quick try for linux: `cd libOTe/cryptoTools/thirdparty/linux/`, `bash all.get`, `cd` back to `libOTe`, `cmake .` and then `make -j`
  * For NTL with GMP and gf2x, `cd ./thirdparty`, and run `all.get`. Then, you can run `cmake .` in  SpOT-PSI folder, and then `make -j`  

NOTE: if you meet prolem with NTL, try to do the following and read [`Building and using NTL with GMP`](https://www.shoup.net/ntl/doc/tour-gmp.html): 
###### change ntl code

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

In lip.h (line 645), change "class _ntl_general_rem_one_struct" to be "struct _ntl_general_rem_one_struct;".

### Building the Project
After cloning project from git, 
##### Windows:
1. build cryptoTools,libOTe, and libOPRF projects in order.
2. add argument for bOPRFmain project (for example: -u)
3. run bOPRFmain project
 
##### Linux:
1. make (requirements: `CMake`, `Make`, `g++` or similar)
2. for test:
	./bin/frontend.exe -t


## Running the code
The database is generated randomly. The outputs include the average online/offline/total runtime that displayed on the screen and output.txt. 
#### Flags:
    -u		unit test which computes PSI of 2 paries, each with set size 2^8 in semi-honest setting
	-n		log of set size (e.g. n=8 => setsize =2^8)
	-N		set size
	-echd	        evaluating DH-based PSI
	                 -c: curve type (0: k283 vs 1: Curve25519)
	-p              evaluating our protocols (0: `spot-fast` vs 1: `spot-low`)
	-t		number of thread
	-ip		ip address and port (eg. 172.31.22.179:1212)
#### Examples: 
##### 1. Unit test:
	./bin/frontend.exe -u
	
##### 2. PSI:
ECHD

	./bin/frontend.exe -r 1 -echd -c 0 -n 8 -ip 172.31.77.224:1212
	& ./bin/frontend.exe -r 0 -echd -c 0 -n 8 -ip 172.31.77.224:1212

	
`spot-fast`

	/bin/frontend.exe -r 1 -n 8 -t 1 -p 0 -ip 172.31.77.224:1212
	& /bin/frontend.exe -r 1 -n 8 -t 1 -p 0 -ip 172.31.77.224:1212
 
`spot-low`

	/bin/frontend.exe -r 1 -n 8 -t 1 -p 1 -ip 172.31.77.224:1212
	& /bin/frontend.exe -r 1 -n 8 -t 1 -p 1 -ip 172.31.77.224:1212
 
		
## Help
For any questions on building or running the library, please contact [`Ni Trieu`](http://people.oregonstate.edu/~trieun/) at trieun at oregonstate dot edu

