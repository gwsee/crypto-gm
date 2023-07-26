# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [0.2.20](///compare/v0.2.19...v0.2.20) (2022-05-27)


### Features

* **agg.go:** fix 3 part aggregation signature ([4c853ad](///commit/4c853add6ff99b2626331d7ef186b36078e04666))
* **all:** all ([de8298c](///commit/de8298ca0674ac5d2a1cd2029a1e8dd04c0a52cd))
* **all:** finish code ([44efe39](///commit/44efe3999c84b9946a427082b63a307b0ad79f55))
* **all:** move code repository to new address ([fba3484](///commit/fba3484d83a4197b3734e5f04304d3da879af994))
* **all:** replease ultrumesh to hyperchain ([6002afb](///commit/6002afb795ee4c341e98550d7196ea5516f848f2))
* **gm_sm3_test.go:** add unit testing, TestResetWithDefaultID ([1343c07](///commit/1343c07f50b977bf4bff9390865e1d22707dac72))

<a name="0.2.19"></a>
## [0.2.19](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.17-1...v0.2.19) (2022-03-09)


### Features

* **sm2:** add benchmark for tjfocsm2 ([2a5b4f4](http://git.hyperchain.cn/ultramesh/crypto/commits/2a5b4f4))
* **test:** add test suites ([1970302](http://git.hyperchain.cn/ultramesh/crypto/commits/1970302))



<a name="0.2.17-1"></a>
## [0.2.17-1](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.17...v0.2.17-1) (2021-07-14)


### Bug Fixes

* **sm4.go:** #flato-3735, fix decrypt ([7e28be6](http://git.hyperchain.cn/ultramesh/crypto/commits/7e28be6))



<a name="0.2.17"></a>
## [0.2.17](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.16-2...v0.2.17) (2021-06-04)



<a name="0.2.16-2"></a>
## [0.2.16-2](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.15-2...v0.2.16-2) (2021-05-31)


### Features

* **sm3:** opt pad ([1a43159](http://git.hyperchain.cn/ultramesh/crypto/commits/1a43159))



<a name="0.2.16-1"></a>
## [0.2.16-1](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.15-1...v0.2.16-1) (2021-05-18)


### Bug Fixes

* **sm3:** fix sm3.unhandled=params ([4b2aca8](http://git.hyperchain.cn/ultramesh/crypto/commits/4b2aca8))


### Features

* **all:** all ([65b3378](http://git.hyperchain.cn/ultramesh/crypto/commits/65b3378))
* **all:** all ([ad37244](http://git.hyperchain.cn/ultramesh/crypto/commits/ad37244))
* **internal/sm3:** sum ([d1445d2](http://git.hyperchain.cn/ultramesh/crypto/commits/d1445d2))



<a name="0.2.16-1"></a>
## [0.2.16-1](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.16...v0.2.16-1) (2021-05-18)


### Bug Fixes

* **sm3:** fix sm3.unhandled=params ([4b2aca8](http://git.hyperchain.cn/ultramesh/crypto/commits/4b2aca8))



<a name="0.2.16"></a>
## [0.2.16](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.1.6...v0.2.16) (2021-05-14)


### Bug Fixes

* **asm:** #flato-3470, asm ([22ccdae](http://git.hyperchain.cn/ultramesh/crypto/commits/22ccdae)), closes [#flato-3470](http://git.hyperchain.cn/ultramesh/crypto/issues/flato-3470)
* **evm:** #flato-2584 fix evm fuzz test compile failed ([695f15e](http://git.hyperchain.cn/ultramesh/crypto/commits/695f15e))
* **sm2:** add isInit in GenerateSM2KeyForDH to fix idA and B must be different ([47baa16](http://git.hyperchain.cn/ultramesh/crypto/commits/47baa16))
* **sm2:** add sm2 sign and verifySignature function ([3fe7349](http://git.hyperchain.cn/ultramesh/crypto/commits/3fe7349))
* **sm2:** add test function for privateKey.Public() ([87d7cb0](http://git.hyperchain.cn/ultramesh/crypto/commits/87d7cb0))
* **sm2:** change p256Precomputed to a const value ([40034ba](http://git.hyperchain.cn/ultramesh/crypto/commits/40034ba))
* **sm2:** change SM2Privatekey.k , SM2PublicKey.X, SM2PublicKey.Y from []byte to [32]byte ([faeac3a](http://git.hyperchain.cn/ultramesh/crypto/commits/faeac3a))
* **sm2:** delete arm64 in some test files ([a4e5e5a](http://git.hyperchain.cn/ultramesh/crypto/commits/a4e5e5a))
* **sm2:** delete big.int in sm2_smd64 ([cb13c82](http://git.hyperchain.cn/ultramesh/crypto/commits/cb13c82))
* **sm2:** delete come unsed tests and make combinedMult just compute x ([fa0665f](http://git.hyperchain.cn/ultramesh/crypto/commits/fa0665f))
* **sm2:** delete internal reference in gm package ([243b571](http://git.hyperchain.cn/ultramesh/crypto/commits/243b571))
* **sm2:** delete some movd in arm asm, merge order.s and p256.s to bignum_asm_amd64.s ([170fd6a](http://git.hyperchain.cn/ultramesh/crypto/commits/170fd6a))
* **sm2:** delete some MOVQ in p256.s and ord.s ([fa109a6](http://git.hyperchain.cn/ultramesh/crypto/commits/fa109a6))
* **sm2:** delete some unnecessary memory allocation in sm2.GenerateKey ([b03ec33](http://git.hyperchain.cn/ultramesh/crypto/commits/b03ec33))
* **sm2:** fix some test function ([03ceaf4](http://git.hyperchain.cn/ultramesh/crypto/commits/03ceaf4))
* **sm2:** move a test function which can not complie in 32bit ([a9b4fae](http://git.hyperchain.cn/ultramesh/crypto/commits/a9b4fae))
* **sm2:** repalce MULQ with MULXQ in sm2 ([51cb2ce](http://git.hyperchain.cn/ultramesh/crypto/commits/51cb2ce))
* **sm2:** splite code for amd32 and 64 ([a410ac9](http://git.hyperchain.cn/ultramesh/crypto/commits/a410ac9))
* **sm2:** store p256precomputed in assembly ([2000227](http://git.hyperchain.cn/ultramesh/crypto/commits/2000227))
* **sm2:** update sm2 32bit version to impove verify speed ([b717e3b](http://git.hyperchain.cn/ultramesh/crypto/commits/b717e3b))
* **sm2_test:** update test data in TestVerify for sm2 ([eeb5fdb](http://git.hyperchain.cn/ultramesh/crypto/commits/eeb5fdb))
* **sm2, sm3, sm9:** fix golint ([fb753e4](http://git.hyperchain.cn/ultramesh/crypto/commits/fb753e4))
* **sm2/P256Inverse:** fix p256Inverse mod p ([bce546b](http://git.hyperchain.cn/ultramesh/crypto/commits/bce546b))
* **sm2/sm2BaseMult:** chang sm2Point struct and some function args ([d36b1ef](http://git.hyperchain.cn/ultramesh/crypto/commits/d36b1ef))
* **sm2/sm2PointAdd:** add 2  pointAdd functions of sm2 ([5128293](http://git.hyperchain.cn/ultramesh/crypto/commits/5128293))
* **sm2/sm2PointAdd:** add sm2PointAddAsm function ([ad4d166](http://git.hyperchain.cn/ultramesh/crypto/commits/ad4d166))
* **sm2/sm2PointDouble:** add pointDoubleAsm function ([7183ba2](http://git.hyperchain.cn/ultramesh/crypto/commits/7183ba2))
* **sm3:** add arg in update to reduce alloc/op ([b6679f5](http://git.hyperchain.cn/ultramesh/crypto/commits/b6679f5))
* **sm3:** add arg in update to reduce alloc/op ([d9f38db](http://git.hyperchain.cn/ultramesh/crypto/commits/d9f38db))
* **sm3:** add NewWithID in sm3 ([a73b78b](http://git.hyperchain.cn/ultramesh/crypto/commits/a73b78b))
* **sm3:** add test for sm3.Sum, delete copy in sm3.Sum ([a72f405](http://git.hyperchain.cn/ultramesh/crypto/commits/a72f405))
* **sm3:** add TestHashBeforeSM2, delete some internal reference in sm3_test ([54538eb](http://git.hyperchain.cn/ultramesh/crypto/commits/54538eb))
* **sm3:** change sum function to get hash value from in slice ([189c07f](http://git.hyperchain.cn/ultramesh/crypto/commits/189c07f))
* **sm3:** repalce internal.New() with sm3.New() in sm2_ecc.go ([71828d3](http://git.hyperchain.cn/ultramesh/crypto/commits/71828d3))
* **sm3,sm2:** delete internal reference in sm2 and sm3 ([2c902f9](http://git.hyperchain.cn/ultramesh/crypto/commits/2c902f9))
* **sm9:** fix bug in sm9 with 32bit version ([861ebd7](http://git.hyperchain.cn/ultramesh/crypto/commits/861ebd7))
* **test:** add test data about sm2, sm3, sm4 ([d70484b](http://git.hyperchain.cn/ultramesh/crypto/commits/d70484b))
* **test:** compare openssl result in test function for sm3, sm4 ([9178a03](http://git.hyperchain.cn/ultramesh/crypto/commits/9178a03))
* **test:** fix ci error in sm3_test.go and sm4_test.go ([3dc5527](http://git.hyperchain.cn/ultramesh/crypto/commits/3dc5527))


### Features

* **all:** #flato-3031, crypto engine ([0463fd7](http://git.hyperchain.cn/ultramesh/crypto/commits/0463fd7)), closes [#flato-3031](http://git.hyperchain.cn/ultramesh/crypto/issues/flato-3031)
* **all:** all ([65b3378](http://git.hyperchain.cn/ultramesh/crypto/commits/65b3378))
* **all:** all ([ad37244](http://git.hyperchain.cn/ultramesh/crypto/commits/ad37244))
* **batchverify:** add unittest and fix bugs ([fd6a5bd](http://git.hyperchain.cn/ultramesh/crypto/commits/fd6a5bd))
* **batchverify:** add unittest and mult mode convertion(bug to fix) ([218914c](http://git.hyperchain.cn/ultramesh/crypto/commits/218914c))
* **batchverify:** amend interface ([fd2eef1](http://git.hyperchain.cn/ultramesh/crypto/commits/fd2eef1))
* **batchverify:** amend memory allocation ([0af62fa](http://git.hyperchain.cn/ultramesh/crypto/commits/0af62fa))
* **batchverify:** finish computation code ([a87f66c](http://git.hyperchain.cn/ultramesh/crypto/commits/a87f66c))
* **batchverify:** lint error ([5c645de](http://git.hyperchain.cn/ultramesh/crypto/commits/5c645de))
* **batchverify:** lint error ([8411733](http://git.hyperchain.cn/ultramesh/crypto/commits/8411733))
* **build:** add noasm tag ([2c68a8a](http://git.hyperchain.cn/ultramesh/crypto/commits/2c68a8a))
* **build:** mac，mips build ([1bf272f](http://git.hyperchain.cn/ultramesh/crypto/commits/1bf272f))
* **csp:** #flato-2289, arm64 build ([30c8354](http://git.hyperchain.cn/ultramesh/crypto/commits/30c8354)), closes [#flato-2289](http://git.hyperchain.cn/ultramesh/crypto/issues/flato-2289)
* **csp:** fix rdrand ([281c8ac](http://git.hyperchain.cn/ultramesh/crypto/commits/281c8ac))
* **cuda:** #flato-1335, add cuda ([adff3cd](http://git.hyperchain.cn/ultramesh/crypto/commits/adff3cd)), closes [#flato-1335](http://git.hyperchain.cn/ultramesh/crypto/issues/flato-1335)
* **cuda:** #flato-1335, add cuda self-test ([e5991ee](http://git.hyperchain.cn/ultramesh/crypto/commits/e5991ee)), closes [#flato-1335](http://git.hyperchain.cn/ultramesh/crypto/issues/flato-1335)
* **cuda:** #flato-3437, cuda ([3dcc324](http://git.hyperchain.cn/ultramesh/crypto/commits/3dcc324)), closes [#flato-3437](http://git.hyperchain.cn/ultramesh/crypto/issues/flato-3437)
* **cuda:** cuda ([1ed208f](http://git.hyperchain.cn/ultramesh/crypto/commits/1ed208f))
* **cuda:** finish ([ef77479](http://git.hyperchain.cn/ultramesh/crypto/commits/ef77479))
* **cuda:** modify README.md ([b7c170a](http://git.hyperchain.cn/ultramesh/crypto/commits/b7c170a))
* **cuda:** modify VerifySignatureGPU ([90337d6](http://git.hyperchain.cn/ultramesh/crypto/commits/90337d6))
* **cuda:** signature padding fix ([b8cffb6](http://git.hyperchain.cn/ultramesh/crypto/commits/b8cffb6))
* **cuda/sm2.go:** modify VerifySignatureGPU with []uint8 result ([f48cb93](http://git.hyperchain.cn/ultramesh/crypto/commits/f48cb93))
* **cuda/sm2.go:** optimize data transfer in VerifySignatureGPU(...) and reduce copy ([53ac643](http://git.hyperchain.cn/ultramesh/crypto/commits/53ac643))
* **fit32bit:** main code and unittest ([fa6f50c](http://git.hyperchain.cn/ultramesh/crypto/commits/fa6f50c))
* **internal:** remove HasADX ([cf27cf0](http://git.hyperchain.cn/ultramesh/crypto/commits/cf27cf0))
* **internal/sm2:** #flato-3028, fix unsafe package usage ([c6cdebd](http://git.hyperchain.cn/ultramesh/crypto/commits/c6cdebd))
* **internal/sm3:** sum ([d1445d2](http://git.hyperchain.cn/ultramesh/crypto/commits/d1445d2))
* **sign:** batchsign test ([d55f6dd](http://git.hyperchain.cn/ultramesh/crypto/commits/d55f6dd))
* **sign:** batchsign test ([cde84f0](http://git.hyperchain.cn/ultramesh/crypto/commits/cde84f0))
* **sm2:** add SignBatch interface ([6e1472a](http://git.hyperchain.cn/ultramesh/crypto/commits/6e1472a))
* **sm2:** bigfix ([268785a](http://git.hyperchain.cn/ultramesh/crypto/commits/268785a))
* **sm2Curve:** IsOnCurve ([032c5f4](http://git.hyperchain.cn/ultramesh/crypto/commits/032c5f4))
* **sm2ScalarMult:** Z!=1 bug fixed ([be52487](http://git.hyperchain.cn/ultramesh/crypto/commits/be52487))
* **smallordermul:** unittest ([fa2ae7b](http://git.hyperchain.cn/ultramesh/crypto/commits/fa2ae7b))
* lint error ([a2a7778](http://git.hyperchain.cn/ultramesh/crypto/commits/a2a7778))
* lint error ([9d5a9ec](http://git.hyperchain.cn/ultramesh/crypto/commits/9d5a9ec))
* **batchverify.go:** check step1 and structure ([8c32c84](http://git.hyperchain.cn/ultramesh/crypto/commits/8c32c84))
* merge branch ([f531275](http://git.hyperchain.cn/ultramesh/crypto/commits/f531275))
* **123:** 123 ([a907aa3](http://git.hyperchain.cn/ultramesh/crypto/commits/a907aa3))
* **all:** modify project struct, remove openssl code ([ac3ff54](http://git.hyperchain.cn/ultramesh/crypto/commits/ac3ff54))
* **batchverify.go:** add pointR computation ([4930897](http://git.hyperchain.cn/ultramesh/crypto/commits/4930897))
* **batchverify.go:** add pointR computation ([5b720c8](http://git.hyperchain.cn/ultramesh/crypto/commits/5b720c8))
* **bignum_asm.go:** rebase ([417ec09](http://git.hyperchain.cn/ultramesh/crypto/commits/417ec09))
* **csp:** add RDRAND instruction to generate randomness ([292c32b](http://git.hyperchain.cn/ultramesh/crypto/commits/292c32b))
* **csp:** add RDRAND instruction to generate randomness ([fbf0628](http://git.hyperchain.cn/ultramesh/crypto/commits/fbf0628))
* **go.mod:** delete some third party reliance ([20e0d6d](http://git.hyperchain.cn/ultramesh/crypto/commits/20e0d6d))
* **mm.s:** mm.s ([50edf8e](http://git.hyperchain.cn/ultramesh/crypto/commits/50edf8e))
* **modify:** modify ([16ce9d6](http://git.hyperchain.cn/ultramesh/crypto/commits/16ce9d6))
* **orderSqr:** orderSqr ([5c2c0a2](http://git.hyperchain.cn/ultramesh/crypto/commits/5c2c0a2))
* **p256.s:** p256Mul ([9536572](http://git.hyperchain.cn/ultramesh/crypto/commits/9536572))
* **p256Sqr:** p256Sqr ([8c61981](http://git.hyperchain.cn/ultramesh/crypto/commits/8c61981))
* **sm2:** add arm64 asm in sm2 ([fef971a](http://git.hyperchain.cn/ultramesh/crypto/commits/fef971a))
* **sm2:** redc algo ([942984a](http://git.hyperchain.cn/ultramesh/crypto/commits/942984a))
* **sm2:** sm2 ([42d7b46](http://git.hyperchain.cn/ultramesh/crypto/commits/42d7b46))
* **sm2,sm3:** inline ([56296c1](http://git.hyperchain.cn/ultramesh/crypto/commits/56296c1))
* **sm2/CombinedMult:** add CombinedMult in sm2 curve ([6b92458](http://git.hyperchain.cn/ultramesh/crypto/commits/6b92458))
* **sm2/sm2BaseMult:** add base point multiplication, fix bug in double point ([5997114](http://git.hyperchain.cn/ultramesh/crypto/commits/5997114))
* **sm2/sm2PointAdd:** add point add function ([bffce4f](http://git.hyperchain.cn/ultramesh/crypto/commits/bffce4f))
* **sm2/sm2ScalarMult:** add sm2ScalarMult function ([c403232](http://git.hyperchain.cn/ultramesh/crypto/commits/c403232))
* **sm3:** add sm3 asm ([5fc390c](http://git.hyperchain.cn/ultramesh/crypto/commits/5fc390c))
* **sm3:** add sm3 hash function in go ([e4917aa](http://git.hyperchain.cn/ultramesh/crypto/commits/e4917aa))
* **sm3:** sm3 ([bdc7a9c](http://git.hyperchain.cn/ultramesh/crypto/commits/bdc7a9c))
* **sm3:** sm3 ([4280861](http://git.hyperchain.cn/ultramesh/crypto/commits/4280861))
* **sm3,sm2:** remove arm64 tag ([c4eddc3](http://git.hyperchain.cn/ultramesh/crypto/commits/c4eddc3))
* **sm3.go:** fix sm3 with id ([0283e08](http://git.hyperchain.cn/ultramesh/crypto/commits/0283e08))
* **sm3/sm3.go:** fix arm build fail ([bd47a53](http://git.hyperchain.cn/ultramesh/crypto/commits/bd47a53))
* **sm4:** #flato-1331, modify sm4 ([bc0b627](http://git.hyperchain.cn/ultramesh/crypto/commits/bc0b627)), closes [#flato-1331](http://git.hyperchain.cn/ultramesh/crypto/issues/flato-1331)
* **sm9:** fix arm build fail ([f1b23f8](http://git.hyperchain.cn/ultramesh/crypto/commits/f1b23f8))
* **sm9,sm3:** fix arm build fail ([f212c90](http://git.hyperchain.cn/ultramesh/crypto/commits/f212c90))
* **sonar:** add sonar condigration file ([127952a](http://git.hyperchain.cn/ultramesh/crypto/commits/127952a))
* **sqr:** sqr and mul ([d288f63](http://git.hyperchain.cn/ultramesh/crypto/commits/d288f63))
* **step1:** pre operation ([f9cca82](http://git.hyperchain.cn/ultramesh/crypto/commits/f9cca82))



<a name="0.2.15-2"></a>
## [0.2.15-2](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.15-1...v0.2.15-2) (2021-05-18)


### Bug Fixes

* **sm3:** fix sm3.unhandled=params ([1b5238c](http://git.hyperchain.cn/ultramesh/crypto/commits/1b5238c))



<a name="0.2.15-1"></a>
## [0.2.15-1](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.15...v0.2.15-1) (2021-05-10)


### Features

* **internal:** remove HasADX ([cf27cf0](http://git.hyperchain.cn/ultramesh/crypto/commits/cf27cf0))



<a name="0.2.15"></a>
## [0.2.15](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.14-1...v0.2.15) (2021-05-07)


### Bug Fixes

* **asm:** #flato-3470, asm ([22ccdae](http://git.hyperchain.cn/ultramesh/crypto/commits/22ccdae)), closes [#flato-3470](http://git.hyperchain.cn/ultramesh/crypto/issues/flato-3470)



<a name="0.2.14-1"></a>
## [0.2.14-1](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.14...v0.2.14-1) (2021-04-28)


### Features

* **cuda:** #flato-3437, cuda ([3dcc324](http://git.hyperchain.cn/ultramesh/crypto/commits/3dcc324)), closes [#flato-3437](http://git.hyperchain.cn/ultramesh/crypto/issues/flato-3437)



<a name="0.2.14"></a>
## [0.2.14](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.13...v0.2.14) (2021-02-01)


### Features

* **all:** #flato-3031, crypto engine ([0463fd7](http://git.hyperchain.cn/ultramesh/crypto/commits/0463fd7)), closes [#flato-3031](http://git.hyperchain.cn/ultramesh/crypto/issues/flato-3031)



<a name="0.2.13"></a>
## [0.2.13](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.12-1...v0.2.13) (2021-01-07)



<a name="0.2.12"></a>
## [0.2.12](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.11...v0.2.12) (2020-12-11)



<a name="0.2.11"></a>
## [0.2.11](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.10...v0.2.11) (2020-11-28)



<a name="0.2.10"></a>
## [0.2.10](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.9...v0.2.10) (2020-10-16)



<a name="0.2.9"></a>
## [0.2.9](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.8...v0.2.9) (2020-09-21)



<a name="0.2.8"></a>
## [0.2.8](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.7...v0.2.8) (2020-09-18)



<a name="0.2.7"></a>
## [0.2.7](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.6...v0.2.7) (2020-09-03)



<a name="0.2.6"></a>
## [0.2.6](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.5...v0.2.6) (2020-08-13)



<a name="0.2.5"></a>
## [0.2.5](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.4...v0.2.5) (2020-07-29)



<a name="0.2.4"></a>
## [0.2.4](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.3...v0.2.4) (2020-07-25)



<a name="0.2.3"></a>
## [0.2.3](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.2...v0.2.3) (2020-07-21)



<a name="0.2.2"></a>
## [0.2.2](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.1...v0.2.2) (2020-07-17)



<a name="0.2.1"></a>
## [0.2.1](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.0...v0.2.1) (2020-06-24)



<a name="0.2.0"></a>
# [0.2.0](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.1.7...v0.2.0) (2020-05-28)



<a name="0.1.7"></a>
## [0.1.7](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.1.6...v0.1.7) (2020-05-27)



<a name="0.2.12"></a>
## [0.2.12](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.11...v0.2.12) (2020-12-11)


### Features

* **build:** mac，mips build ([1bf272f](http://git.hyperchain.cn/ultramesh/crypto/commits/1bf272f))



<a name="0.2.11"></a>
## [0.2.11](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.10...v0.2.11) (2020-11-28)


### Bug Fixes

* **evm:** #flato-2584 fix evm fuzz test compile failed ([695f15e](http://git.hyperchain.cn/ultramesh/crypto/commits/695f15e))


### Features

* **cuda:** #flato-1335, add cuda self-test ([e5991ee](http://git.hyperchain.cn/ultramesh/crypto/commits/e5991ee)), closes [#flato-1335](http://git.hyperchain.cn/ultramesh/crypto/issues/flato-1335)
* **cuda:** cuda ([1ed208f](http://git.hyperchain.cn/ultramesh/crypto/commits/1ed208f))
* **cuda:** finish ([ef77479](http://git.hyperchain.cn/ultramesh/crypto/commits/ef77479))
* **cuda:** modify VerifySignatureGPU ([90337d6](http://git.hyperchain.cn/ultramesh/crypto/commits/90337d6))
* **cuda:** signature padding fix ([b8cffb6](http://git.hyperchain.cn/ultramesh/crypto/commits/b8cffb6))
* **cuda/sm2.go:** modify VerifySignatureGPU with []uint8 result ([f48cb93](http://git.hyperchain.cn/ultramesh/crypto/commits/f48cb93))
* **cuda/sm2.go:** optimize data transfer in VerifySignatureGPU(...) and reduce copy ([53ac643](http://git.hyperchain.cn/ultramesh/crypto/commits/53ac643))



<a name="0.2.10"></a>
## [0.2.10](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.9...v0.2.10) (2020-10-16)


### Features

* **csp:** #flato-2289, arm64 build ([30c8354](http://git.hyperchain.cn/ultramesh/crypto/commits/30c8354)), closes [#flato-2289](http://git.hyperchain.cn/ultramesh/crypto/issues/flato-2289)



<a name="0.2.9"></a>
## [0.2.9](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.8...v0.2.9) (2020-09-21)


### Features

* **batchverify:** amend memory allocation ([0af62fa](http://git.hyperchain.cn/ultramesh/crypto/commits/0af62fa))



<a name="0.2.8"></a>
## [0.2.8](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.7...v0.2.8) (2020-09-18)


### Features

* **batchverify:** add unittest and fix bugs ([fd6a5bd](http://git.hyperchain.cn/ultramesh/crypto/commits/fd6a5bd))
* **batchverify:** add unittest and mult mode convertion(bug to fix) ([218914c](http://git.hyperchain.cn/ultramesh/crypto/commits/218914c))
* **batchverify:** amend interface ([fd2eef1](http://git.hyperchain.cn/ultramesh/crypto/commits/fd2eef1))
* **batchverify:** finish computation code ([a87f66c](http://git.hyperchain.cn/ultramesh/crypto/commits/a87f66c))
* **batchverify:** lint error ([5c645de](http://git.hyperchain.cn/ultramesh/crypto/commits/5c645de))
* **batchverify:** lint error ([8411733](http://git.hyperchain.cn/ultramesh/crypto/commits/8411733))
* **batchverify.go:** add pointR computation ([4930897](http://git.hyperchain.cn/ultramesh/crypto/commits/4930897))
* **batchverify.go:** add pointR computation ([5b720c8](http://git.hyperchain.cn/ultramesh/crypto/commits/5b720c8))
* **batchverify.go:** check step1 and structure ([8c32c84](http://git.hyperchain.cn/ultramesh/crypto/commits/8c32c84))
* **bignum_asm.go:** rebase ([417ec09](http://git.hyperchain.cn/ultramesh/crypto/commits/417ec09))
* **csp:** add RDRAND instruction to generate randomness ([292c32b](http://git.hyperchain.cn/ultramesh/crypto/commits/292c32b))
* **csp:** add RDRAND instruction to generate randomness ([fbf0628](http://git.hyperchain.cn/ultramesh/crypto/commits/fbf0628))
* **csp:** fix rdrand ([281c8ac](http://git.hyperchain.cn/ultramesh/crypto/commits/281c8ac))
* **fit32bit:** main code and unittest ([fa6f50c](http://git.hyperchain.cn/ultramesh/crypto/commits/fa6f50c))
* **sign:** batchsign test ([d55f6dd](http://git.hyperchain.cn/ultramesh/crypto/commits/d55f6dd))
* **sign:** batchsign test ([cde84f0](http://git.hyperchain.cn/ultramesh/crypto/commits/cde84f0))
* **sm2:** add SignBatch interface ([6e1472a](http://git.hyperchain.cn/ultramesh/crypto/commits/6e1472a))
* **sm2:** bigfix ([268785a](http://git.hyperchain.cn/ultramesh/crypto/commits/268785a))
* **sm2ScalarMult:** Z!=1 bug fixed ([be52487](http://git.hyperchain.cn/ultramesh/crypto/commits/be52487))
* **smallordermul:** unittest ([fa2ae7b](http://git.hyperchain.cn/ultramesh/crypto/commits/fa2ae7b))
* lint error ([a2a7778](http://git.hyperchain.cn/ultramesh/crypto/commits/a2a7778))
* lint error ([9d5a9ec](http://git.hyperchain.cn/ultramesh/crypto/commits/9d5a9ec))
* merge branch ([f531275](http://git.hyperchain.cn/ultramesh/crypto/commits/f531275))
* **step1:** pre operation ([f9cca82](http://git.hyperchain.cn/ultramesh/crypto/commits/f9cca82))



<a name="0.2.7"></a>
## [0.2.7](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.6...v0.2.7) (2020-09-03)


### Features

* **cuda:** #flato-1335, add cuda ([adff3cd](http://git.hyperchain.cn/ultramesh/crypto/commits/adff3cd)), closes [#flato-1335](http://git.hyperchain.cn/ultramesh/crypto/issues/flato-1335)
* **cuda:** modify README.md ([b7c170a](http://git.hyperchain.cn/ultramesh/crypto/commits/b7c170a))
* **sm2Curve:** IsOnCurve ([032c5f4](http://git.hyperchain.cn/ultramesh/crypto/commits/032c5f4))



<a name="0.2.6"></a>
## [0.2.6](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.5...v0.2.6) (2020-08-13)


### Bug Fixes

* **sm2:** delete some movd in arm asm, merge order.s and p256.s to bignum_asm_amd64.s ([170fd6a](http://git.hyperchain.cn/ultramesh/crypto/commits/170fd6a))
* **sm3:** add test for sm3.Sum, delete copy in sm3.Sum ([a72f405](http://git.hyperchain.cn/ultramesh/crypto/commits/a72f405))


### Features

* **go.mod:** delete some third party reliance ([20e0d6d](http://git.hyperchain.cn/ultramesh/crypto/commits/20e0d6d))
* **sm2:** add arm64 asm in sm2 ([fef971a](http://git.hyperchain.cn/ultramesh/crypto/commits/fef971a))



<a name="0.2.5"></a>
## [0.2.5](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.4...v0.2.5) (2020-07-29)


### Bug Fixes

* **sm2:** move a test function which can not complie in 32bit ([a9b4fae](http://git.hyperchain.cn/ultramesh/crypto/commits/a9b4fae))
* **sm2:** update sm2 32bit version to impove verify speed ([b717e3b](http://git.hyperchain.cn/ultramesh/crypto/commits/b717e3b))
* **sm9:** fix bug in sm9 with 32bit version ([861ebd7](http://git.hyperchain.cn/ultramesh/crypto/commits/861ebd7))



<a name="0.2.4"></a>
## [0.2.4](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.3...v0.2.4) (2020-07-25)


### Bug Fixes

* **sm2:** add test function for privateKey.Public() ([87d7cb0](http://git.hyperchain.cn/ultramesh/crypto/commits/87d7cb0))
* **sm2:** change SM2Privatekey.k , SM2PublicKey.X, SM2PublicKey.Y from []byte to [32]byte ([faeac3a](http://git.hyperchain.cn/ultramesh/crypto/commits/faeac3a))
* **sm2:** delete some unnecessary memory allocation in sm2.GenerateKey ([b03ec33](http://git.hyperchain.cn/ultramesh/crypto/commits/b03ec33))
* **sm2_test:** update test data in TestVerify for sm2 ([eeb5fdb](http://git.hyperchain.cn/ultramesh/crypto/commits/eeb5fdb))



<a name="0.2.3"></a>
## [0.2.3](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.2...v0.2.3) (2020-07-21)


### Bug Fixes

* **sm2:** add isInit in GenerateSM2KeyForDH to fix idA and B must be different ([47baa16](http://git.hyperchain.cn/ultramesh/crypto/commits/47baa16))
* **sm2:** delete some MOVQ in p256.s and ord.s ([fa109a6](http://git.hyperchain.cn/ultramesh/crypto/commits/fa109a6))
* **sm2:** repalce MULQ with MULXQ in sm2 ([51cb2ce](http://git.hyperchain.cn/ultramesh/crypto/commits/51cb2ce))
* **sm3:** add TestHashBeforeSM2, delete some internal reference in sm3_test ([54538eb](http://git.hyperchain.cn/ultramesh/crypto/commits/54538eb))
* **test:** compare openssl result in test function for sm3, sm4 ([9178a03](http://git.hyperchain.cn/ultramesh/crypto/commits/9178a03))
* **test:** fix ci error in sm3_test.go and sm4_test.go ([3dc5527](http://git.hyperchain.cn/ultramesh/crypto/commits/3dc5527))


### Features

* **sonar:** add sonar condigration file ([127952a](http://git.hyperchain.cn/ultramesh/crypto/commits/127952a))



<a name="0.2.2"></a>
## [0.2.2](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.1...v0.2.2) (2020-07-17)


### Bug Fixes

* **sm3:** change sum function to get hash value from in slice ([189c07f](http://git.hyperchain.cn/ultramesh/crypto/commits/189c07f))
* **test:** add test data about sm2, sm3, sm4 ([d70484b](http://git.hyperchain.cn/ultramesh/crypto/commits/d70484b))


### Features

* **all:** modify project struct, remove openssl code ([ac3ff54](http://git.hyperchain.cn/ultramesh/crypto/commits/ac3ff54))
* **sm3/sm3.go:** fix arm build fail ([bd47a53](http://git.hyperchain.cn/ultramesh/crypto/commits/bd47a53))
* **sm9:** fix arm build fail ([f1b23f8](http://git.hyperchain.cn/ultramesh/crypto/commits/f1b23f8))
* **sm9,sm3:** fix arm build fail ([f212c90](http://git.hyperchain.cn/ultramesh/crypto/commits/f212c90))



<a name="0.2.1"></a>
## [0.2.1](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.2.0...v0.2.1) (2020-06-24)


### Features

* **sm3.go:** fix sm3 with id ([0283e08](http://git.hyperchain.cn/ultramesh/crypto/commits/0283e08))



<a name="0.2.0"></a>
# [0.2.0](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.1.7...v0.2.0) (2020-05-28)


### Bug Fixes

* **sm3:** add arg in update to reduce alloc/op ([b6679f5](http://git.hyperchain.cn/ultramesh/crypto/commits/b6679f5))
* **sm3:** add arg in update to reduce alloc/op ([d9f38db](http://git.hyperchain.cn/ultramesh/crypto/commits/d9f38db))


### Features

* **sm3:** sm3 ([bdc7a9c](http://git.hyperchain.cn/ultramesh/crypto/commits/bdc7a9c))
* **sm3:** sm3 ([4280861](http://git.hyperchain.cn/ultramesh/crypto/commits/4280861))



<a name="0.1.7"></a>
## [0.1.7](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.1.6...v0.1.7) (2020-05-27)


### Bug Fixes

* **sm2:** add sm2 sign and verifySignature function ([3fe7349](http://git.hyperchain.cn/ultramesh/crypto/commits/3fe7349))
* **sm2:** change p256Precomputed to a const value ([40034ba](http://git.hyperchain.cn/ultramesh/crypto/commits/40034ba))
* **sm2:** delete arm64 in some test files ([a4e5e5a](http://git.hyperchain.cn/ultramesh/crypto/commits/a4e5e5a))
* **sm2:** delete big.int in sm2_smd64 ([cb13c82](http://git.hyperchain.cn/ultramesh/crypto/commits/cb13c82))
* **sm2:** delete come unsed tests and make combinedMult just compute x ([fa0665f](http://git.hyperchain.cn/ultramesh/crypto/commits/fa0665f))
* **sm2:** delete internal reference in gm package ([243b571](http://git.hyperchain.cn/ultramesh/crypto/commits/243b571))
* **sm2:** fix some test function ([03ceaf4](http://git.hyperchain.cn/ultramesh/crypto/commits/03ceaf4))
* **sm2:** splite code for amd32 and 64 ([a410ac9](http://git.hyperchain.cn/ultramesh/crypto/commits/a410ac9))
* **sm2:** store p256precomputed in assembly ([2000227](http://git.hyperchain.cn/ultramesh/crypto/commits/2000227))
* **sm2, sm3, sm9:** fix golint ([fb753e4](http://git.hyperchain.cn/ultramesh/crypto/commits/fb753e4))
* **sm2/P256Inverse:** fix p256Inverse mod p ([bce546b](http://git.hyperchain.cn/ultramesh/crypto/commits/bce546b))
* **sm2/sm2BaseMult:** chang sm2Point struct and some function args ([d36b1ef](http://git.hyperchain.cn/ultramesh/crypto/commits/d36b1ef))
* **sm2/sm2PointAdd:** add 2  pointAdd functions of sm2 ([5128293](http://git.hyperchain.cn/ultramesh/crypto/commits/5128293))
* **sm2/sm2PointAdd:** add sm2PointAddAsm function ([ad4d166](http://git.hyperchain.cn/ultramesh/crypto/commits/ad4d166))
* **sm2/sm2PointDouble:** add pointDoubleAsm function ([7183ba2](http://git.hyperchain.cn/ultramesh/crypto/commits/7183ba2))
* **sm3:** add NewWithID in sm3 ([a73b78b](http://git.hyperchain.cn/ultramesh/crypto/commits/a73b78b))
* **sm3:** repalce internal.New() with sm3.New() in sm2_ecc.go ([71828d3](http://git.hyperchain.cn/ultramesh/crypto/commits/71828d3))
* **sm3,sm2:** delete internal reference in sm2 and sm3 ([2c902f9](http://git.hyperchain.cn/ultramesh/crypto/commits/2c902f9))


### Features

* **123:** 123 ([a907aa3](http://git.hyperchain.cn/ultramesh/crypto/commits/a907aa3))
* **mm.s:** mm.s ([50edf8e](http://git.hyperchain.cn/ultramesh/crypto/commits/50edf8e))
* **modify:** modify ([16ce9d6](http://git.hyperchain.cn/ultramesh/crypto/commits/16ce9d6))
* **orderSqr:** orderSqr ([5c2c0a2](http://git.hyperchain.cn/ultramesh/crypto/commits/5c2c0a2))
* **p256.s:** p256Mul ([9536572](http://git.hyperchain.cn/ultramesh/crypto/commits/9536572))
* **p256Sqr:** p256Sqr ([8c61981](http://git.hyperchain.cn/ultramesh/crypto/commits/8c61981))
* **sm2:** redc algo ([942984a](http://git.hyperchain.cn/ultramesh/crypto/commits/942984a))
* **sm2:** sm2 ([42d7b46](http://git.hyperchain.cn/ultramesh/crypto/commits/42d7b46))
* **sm2,sm3:** inline ([56296c1](http://git.hyperchain.cn/ultramesh/crypto/commits/56296c1))
* **sm2/CombinedMult:** add CombinedMult in sm2 curve ([6b92458](http://git.hyperchain.cn/ultramesh/crypto/commits/6b92458))
* **sm2/sm2BaseMult:** add base point multiplication, fix bug in double point ([5997114](http://git.hyperchain.cn/ultramesh/crypto/commits/5997114))
* **sm2/sm2PointAdd:** add point add function ([bffce4f](http://git.hyperchain.cn/ultramesh/crypto/commits/bffce4f))
* **sm2/sm2ScalarMult:** add sm2ScalarMult function ([c403232](http://git.hyperchain.cn/ultramesh/crypto/commits/c403232))
* **sm3:** add sm3 asm ([5fc390c](http://git.hyperchain.cn/ultramesh/crypto/commits/5fc390c))
* **sm3:** add sm3 hash function in go ([e4917aa](http://git.hyperchain.cn/ultramesh/crypto/commits/e4917aa))
* **sm3,sm2:** remove arm64 tag ([c4eddc3](http://git.hyperchain.cn/ultramesh/crypto/commits/c4eddc3))
* **sm4:** #flato-1331, modify sm4 ([bc0b627](http://git.hyperchain.cn/ultramesh/crypto/commits/bc0b627)), closes [#flato-1331](http://git.hyperchain.cn/ultramesh/crypto/issues/flato-1331)
* **sqr:** sqr and mul ([d288f63](http://git.hyperchain.cn/ultramesh/crypto/commits/d288f63))




# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [0.1.6](///compare/v0.1.5...v0.1.6) (2020-04-22)


### Features

* **ci:** modify ci ([6966b57](///commit/6966b57995635e1a1f5e24057e3068d18446e52b))

### [0.1.5](///compare/v0.1.4...v0.1.5) (2020-03-30)


### Features

* **go.mod:** remove crypto package ([57e7ef6](///commit/57e7ef656d4a32732ba1ad303880874733d62f80))

### [0.1.4](///compare/v0.1.3...v0.1.4) (2020-03-16)


### Features

* **guomi:**  modify guomi cgo code struct ([2f7bb39](///commit/2f7bb39627a92695975d2ffe908237db0ebca0db))
* **include:** include ([9bd8525](///commit/9bd8525c53b925a2bbdeb098a72a9a942ca69ecb))
* **openssl:** test ([64c4f86](///commit/64c4f8633f55c3f415f4ac1ca575f387288f2692))
* **sm2:** add GenerateSM2KeyForDH function in sm2.go ([283c8ec](///commit/283c8ec96b56bbf59fe97bb3f367b7506902284a))
* **sm2:** modify ([9efaf0a](///commit/9efaf0aa369a706c71e5c0e9c16f56435c7ab0bb))
* **sm2:** modify SM2PrivateKey.k to SM2PrivateKey.K ([369b884](///commit/369b884c52d53446a25a5d4d1c0ee5cc6c939fa4))
* **sm2.go:** add GetSm2Curve interface ([eef0d6a](///commit/eef0d6ad4f0e440e6b67b32fe2b16c5127fcf9d1))
* **sm3,sm4:** #flato-1156, add GetSM3Hasher, GetSM4Cipher interface ([b56f6e0](///commit/b56f6e03c334b162b7e3819e627a53f080508639)), closes [#flato-1156](///issues/flato-1156)


### Bug Fixes

* **internal/gm_sm2:** delete PrivateKey and PublicKey in internal/gm_sm2.go ([fd3e35b](///commit/fd3e35b329d66677ac17bec2dac657ddd3e050d3))
* **internal/gm_sm2.go:** #flato-1144, fix bug about -w ([fb46041](///commit/fb4604176fa8d66a94b3936b1d9d6e1be135f9ed)), closes [#flato-1144](///issues/flato-1144)
* **internal/test:** fix bug in internal/gm_sm2_test.go ([bc3dab4](///commit/bc3dab4dde21ec8057ffc56843cc403ad99b2c24))
* **sm2:** change sm2 private struct and implement crypto.Signer interface ([e63ef97](///commit/e63ef97ca54f58b04faceea9f6620e1483ec0934))
* **sm2:** Public() return pointer ([8647006](///commit/864700639a22cf93376b9783a7695b8967c712c0))

### [0.1.3](///compare/v0.1.2...v0.1.3) (2020-02-07)


### Features

* **sm2.go,sm4.go:** #float-955, reader ([8a71352](///commit/8a713520df9214279c03d62daf88765a23c7b806)), closes [#float-955](///issues/float-955)
* **sm4.go,sm2.go:** #flato-955, add rand reader ([9a0e895](///commit/9a0e8957de60ffb6eb8d58c49e06e5cc107c1331)), closes [#flato-955](///issues/flato-955)
* **test:** #flato-951, mv test to project crypto ([fabe875](///commit/fabe87551b2b38d623f6952a43a581e2596bbd3e)), closes [#flato-951](///issues/flato-951)


### Bug Fixes

* **sm2_ecc.go:** #flato-1111,fix ecc when data longer than 32 ([6b4c93a](///commit/6b4c93aeae5a26aef541ca3b83e13e55cfbaeba7)), closes [#flato-1111](///issues/flato-1111)

### [0.1.2](///compare/v0.1.1...v0.1.2) (2019-12-13)


### Features

* **sm2_ecc:** ecc ([7c4ead3](///commit/7c4ead32a159277ad50c7da8073d2e07d17bfc1e))

### 0.1.1 (2019-10-29)


### Features

* **.gometalinter.json,sm2_test.go,sm3_test.go,sm4_test.go:** add test to package gm,cover 83% ([41d88cf](///commit/41d88cfa98d4649aaa1f57197338b2e067990fab))
* **all:** init ([a103ed1](///commit/a103ed148a253af6391ada6a9c43693ac74462b9))
* **gitlab-ci:** init go module and add gitlab ci ([79f3d12](///commit/79f3d127f21b94d5e2a246c97b1c2ee16e7a6d13))
* **gitlab-ci:** init go module and add gitlab ci ([955ab7e](///commit/955ab7e6313d7e239d82c70a58b1f8d729a1502a))
* **go.mod:** drop go.sum in repo ([109e94e](///commit/109e94e3e6e0edf64a94be6f7111aa9c0fc6fab5))
* **go.mod:** drop go.sum in repo ([7d55265](///commit/7d552652c5e77300a09d9b270f41a6f1cca8681d))
* **go.mod:** drop go.sum in repo ([b33011d](///commit/b33011db59c6d55a87a825e7238482f599d7d01d))
* **go.mod:** drop go.sum in repo ([ca9b159](///commit/ca9b1593eba4b26a32af3c2228fa297d14238d3c))
* **go.mod:** drop go.sum in repo ([d385f5f](///commit/d385f5f1ab474a6a281c24d01fa69e63cfc2b203))
* **guomi:** first init crypto-gm repo ([5c35c3d](///commit/5c35c3d4646e048725b8d4945ceea322f2f76932))
* **guomi:** remove -L ([8e43317](///commit/8e4331758e42c3d67aaf441220ed917174585b03))
* **guomi:** remove -L ([7337bde](///commit/7337bde1d68622c69376f21226a462cb30ef2f58))
* **guomi:** remove -L ([d241e20](///commit/d241e201b630b9357954117da70ec2ebcf8b1113))
* **guomi:** remove -L ([045f6e8](///commit/045f6e8628794001991c6b2f494d3dca86ff6695))
* **README.md:** add README code example ([2c11b39](///commit/2c11b394daf4d43aecd19ac8910d907ff6af74f6))
* **README.md:** modify README.md ([69c404f](///commit/69c404ff9259298378c224d308779a3f5b1634b2))
* **sm4:** change sm4 to golang ([09d3d69](///commit/09d3d6903a01f3aba49b780e308dede4003bdf3c))
* **sm4:** change sm4 to golang ([9e72c6d](///commit/9e72c6d3b29e651335f694f62a64d60631bdd278))
* **sm4.go:** implement interface in package crypto ([6bce551](///commit/6bce551abfa7844cb6340e43ff3fca2a1b496833))
* **sm4.go:** implement interface in package crypto ([133cc2b](///commit/133cc2bd839d36777a5adc404913e81825d1fe50))
* **sm4.go:** implement key interface ([8a24a5f](///commit/8a24a5fb501bbb68ea6320ce42090338c8de70d6))
* **sm9,sm9.go:** add sm9 ([9809f1c](///commit/9809f1ca14fca94b9f7a8b1e048c65dda9b240da))
* **sm9.go:** add sm9 ([a2c7e89](///commit/a2c7e89d75a4dc3d32089130f3c334e369e0103d))
* **test:** #flato-591,init test freamwork ([90d78d7](///commit/90d78d7b4186ff409c847051fa2e811974a4542c)), closes [#flato-591](///issues/flato-591)
* **test.go:** add some test case, cover 83% ([3d096e6](///commit/3d096e6759ef49104e26bc82045a6051bc57fed8))
* **test/main:** modify test fream ([980f00a](///commit/980f00a01a87b389e1a60dc744111bfac8a5406d))


### Bug Fixes

* **fix:** fix test bug ([2e07a1d](///commit/2e07a1d2683e970c285def9fbe0f2117f0ba6807))
* **fmt.sh:** fix fmt.sh ([3c6d4d3](///commit/3c6d4d35363a6b582e12c790d7ae2410caa57e98))
* **guomi:** #flato-608,generate guomi signature panic ([7d30438](///commit/7d304385d7da1fea5bc932bf76211d56a0f83e9a)), closes [#flato-608](///issues/flato-608)
* **sm2:** sm2 panic when sign ([9191b53](///commit/9191b5300407d6dd4ff237ca388fe9e8d7178444))

## 0.1.0 (2019-08-08)


### Features

* **.gometalinter.json,sm2_test.go,sm3_test.go,sm4_test.go:** add test to package gm,cover 83% ([41d88cf](///commit/41d88cf))
* **all:** init ([a103ed1](///commit/a103ed1))
* **gitlab-ci:** init go module and add gitlab ci ([79f3d12](///commit/79f3d12))
* **go.mod:** drop go.sum in repo ([7d55265](///commit/7d55265))
* **guomi:** first init crypto-gm repo ([5c35c3d](///commit/5c35c3d))
* **README.md:** add README code example ([2c11b39](///commit/2c11b39))
* **sm4:** change sm4 to golang ([9e72c6d](///commit/9e72c6d))
* **sm4.go:** implement interface in package crypto ([133cc2b](///commit/133cc2b))
* **sm4.go:** implement key interface ([8a24a5f](///commit/8a24a5f))
* **sm9,sm9.go:** add sm9 ([9809f1c](///commit/9809f1c))
* **sm9.go:** add sm9 ([a2c7e89](///commit/a2c7e89))
* **test.go:** add some test case, cover 83% ([3d096e6](///commit/3d096e6))
