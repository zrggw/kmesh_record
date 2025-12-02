# kmesh 开发

## 准备工作

在进行 kmesh 开发之前，需要先准备好环境和工具。

### 环境准备

**如何配置 kmesh 环境？** 
配置环境请先阅读 kmesh 的文档（链接：https://kmesh.net/docs/welcome）中 setup/quick-start 和 setup/develop-with-kind 中的内容。需要安装的内容如下：
1. kind（需要先安装docker，docker的安装方法可以参考：https://docs.docker.com/engine/install/ubuntu）
2. kubectl
3. istioctl
4. helm，安装方法可以参考 https://helm.sh/zh/docs/intro/install

实际使用下来，kind 占用的资源还是比较多的，可以减少 nodes 的数量来减少资源占用，如只设置两个 node。

**Linux 环境**
如果没有 Linux 开发机，可以使用 Windows 的 WSL2 来进行开发，WSL2 的安装和配置可以参考微软的官方文档。需要自己安装好 docker，以及解决可能的网络问题。

### 提交PR准备

在编写代码之前，建议先阅读 Kmesh 网站上关于这部分的内容 https://kmesh.net/docs/community/contribute ，阅读CONTRIBUTING文档，https://github.com/kmesh-net/kmesh/blob/main/CONTRIBUTING.md ，了解如何编写和提交 PR。

**在提交之前，有几点需要注意**：
1. 执行 make clean，确保不会提交不必要的内容。
2. 执行 make gen-check，确保代码的格式化正确。（有可能github action也会执行这个命令，但是测试下来 github action 上格式化的结果和本地可能会不一样，需要注意。以及gitub action中的 goimports 检查结果可能会和本地 go 自动格式化的结果不一致。目前还没有细究原因。）
3. 如果有必要，需要进行 E2E 和单元测试。有关这两个测试的内容见 [测试部分](#测试)。
4. 执行 `git commit -s -m "your message"`，**-s** 是必须要添加的，这样确保对 commit 签名，这样才能够通过 PR 审查。

## 测试

在进行测试之前请先阅读 Kmesh 网站上关于测试的部分，然后再进行测试和编写代码。

### 单元测试

单元测试主要是针对某个函数或者某个模块进行测试，确保其功能正确。单元测试的代码一般放在和被测试代码同目录下的 `_test.go` 文件中。

在进行单元测试的时候需要经常用到 `gomonkey` 这个库来进行函数的 mock。有关 `gomonkey` 的使用可以参考其 github 页面：
https://github.com/agiledragon/gomonkey 。
gomonkey 主要是用于对函数进行替换，从而达到 mock 的目的，但是在进行测试的时候一定要主要在 `go test` 命令之后添加 `-gcflags=all=-l`，否则可能会因为编译器优化、函数内联，从而导致 mock 失败，测试出现问题。

此外还需常用到 `fake` 这个库来生成一个假的 k8s client，从而避免在单元测试中依赖真实的 k8s 集群。k8s.io/client-go/kubernetes/fake。

如果不知道如何编写单元测试，可以参考 Kmesh 中已有的单元测试代码，也可以参考其他项目的单元测试代码，如 [Kubernetes](https://github.com/kubernetes/kubernetes) 或者 [Istio](https://github.com/istio/istio)。

**NewSimpleClientset**

fake.NewSimpleClientset 可以用来创建一个假的 k8s client，这个 client 可以用来模拟 k8s 的各种操作，如创建、删除、更新资源等。NewSimpleClientset 还可以接受一些初始的对象，这些对象会被添加到 fake client 中，从而可以在测试中使用这些对象。

**gomonkey**
gomonkey 在进行单元测试的时候需要经常被用到，所以需要了解gomonkey的使用。

gomonkey项目地址在 https://github.com/agiledragon/gomonkey

使用的时候需要注意: 

1. 确保在测试结束后调用Reset方法，以便清理所有的补丁。
2. 使用ApplyFunc或ApplyMethod来替换函数或方法的实现。
3. 可以使用ApplyFuncReturn来指定函数的返回值。
4. go test的时候需要加上 -gcflags="-all=-N -l" 参数，以便禁用编译器优化，确保gomonkey能够正常工作。

gomonkey的实现原理，见 https://bou.ke/blog/monkey-patching-in-go/


### E2E 测试

E2E 测试主要是针对整个系统进行测试，确保各个模块能够协同工作。先阅读 https://kmesh.net/docs/developer-guide/Tests/e2e-test 中的内容，然后再进行测试。

### 本地集群测试

在开发的过程中，如果要测试自己的代码是否生效，可以在创建了 kind 集群之后，使用 `kind load docker-image` 命令把自己编译的 kmesh 镜像加载到 kind 集群中。然后修改 kmesh pod 的 image 为自己编译的镜像。这样就可以在本地集群中测试自己的代码了。
可以参考 [网站文档](https://kmesh.net/docs/setup/develop-with-kind#develop-kmesh-in-kind)。通过 `kubectl edit ds kmesh -n kmesh-system`，在配置文件中的镜像位置来修改 kmesh 的镜像，之后会自动重启 kmesh 的 pod。执行 `make docker` 的时候注意添加
`TAG`，即 `make docker TAG=xxx`，这样可以避免和已有的镜像冲突。

# Kmesh 网站

如果要编写 Kmesh 网站的文档，可以参考以下步骤：
https://kmesh.net/docs/developer-guide/website/create-doc

所有 markdown 文件都需要经过 markdownlint 检查，确保符合规范。因此需要预先安装 markdownlint-cli2。可以在本地安装并检查，不同版本的 markdownlint 可能会有不同的检查结果，这里最好和 Kmesh github action 中使用的版本保持一致。可以先安装最新版本。
具体安装和使用方法见 markdownlint-cli2 的 github 页面：https://github.com/DavidAnson/markdownlint-cli2

新文档需要注意文档的头部需要设置好有关信息，如 title, sidebar_position等。可以参考已有的文档。

**网站效果测试**
可以在本地测试网站的修改是否生效 `npm start`。
在提交PR之后，也可以在 PR 页面中看到网站的效果（见netlify bot的回复）。