## 禁用 Java SSL 协议重商功能（针对 CVE-2011-1473）

### 0x01 在启动命令中添加参数

在程序启动的时候，添加启动参数就 OK 了。

1. 禁用 SSLv3, TLSv1, TLSv1.1, RC4, DES, MD5withRSA, 3DES_EDE_CBC 算法：
    
    ```shell
    -Djdk.tls.disabledAlgorithms=SSLv3,TLSv1,TLSv1.1,RC4,DES,MD5withRSA,3DES_EDE_CBC
    ```

2. 拒绝 tls 协议重商：

    ```shell
    -Djdk.tls.rejectClientInitiatedRenegotiation=true
    ```

3. 限制程序使用的 SSL 版本为 tls1.2 及以上：

    ```shell
    -Dweblogic.security.SSL.minimumProtocolVersion=TLSv1.2
    ```

完整示例：
```shell
java -Djdk.tls.disabledAlgorithms=SSLv3,TLSv1,TLSv1.1,RC4,DES,MD5withRSA,3DES_EDE_CBC -Djdk.tls.rejectClientInitiatedRenegotiation=true -Dweblogic.security.SSL.minimumProtocolVersion=TLSv1.2 {程序}
```

### 0x02 在配置文件中添加参数

如果程序加载默认的安全文件 `java.security`，如：`-Djava.security.properties=/path/to/java.security`
则只需要在 `java.security` 中添加启动参数。

```shell
...
-Djdk.tls.disabledAlgorithms=SSLv3,TLSv1,TLSv1.1,RC4,DES,MD5withRSA,3DES_EDE_CBC 
-Djdk.tls.rejectClientInitiatedRenegotiation=true 
-Dweblogic.security.SSL.minimumProtocolVersion=TLSv1.2
...
```

针对中间件的修复，需要修改其启动脚本或配置。对于 weblogic ，直接修改 `{DOMAIN_HOME}/bin/startWebLogic.sh`，在启动程序语句之前的位置添加如上三句内容，例如：

```shell
...
JAVA_OPTIONS="${JAVA_OPTIONS} -Dweblogic.management.username=${WLS_USER}"
fi

if [ "${WLS_PW}" != "" ] ; then
	JAVA_OPTIONS="${JAVA_OPTIONS} -Dweblogic.management.password=${WLS_PW}"
fi

# 在这里添加启动配置
JAVA_OPTIONS="${JAVA_OPTIONS} -Djdk.tls.disabledAlgorithms=SSLv3,TLSv1,TLSv1.1,RC4,DES,MD5withRSA,3DES_EDE_CBC"
JAVA_OPTIONS="${JAVA_OPTIONS} -Djdk.tls.rejectClientInitiatedRenegotiation=true"
JAVA_OPTIONS="${JAVA_OPTIONS} -Dweblogic.security.SSL.minimumProtocolVersion=TLSv1.2"
export JAVA_OPTIONS

if [ "${MEDREC_WEBLOGIC_CLASSPATH}" != "" ] ; then
	if [ "${CLASSPATH}" != "" ] ; then
		CLASSPATH="${CLASSPATH}${CLASSPATHSEP}${MEDREC_WEBLOGIC_CLASSPATH}"
	else
		CLASSPATH="${MEDREC_WEBLOGIC_CLASSPATH}"
	fi
fi
...
```

其他可能有用的 Java 启动参数参考：

```shell
JAVA_OPTIONS="${JAVA_OPTIONS} -Djdk.tls.disabledAlgorithms=SSLv3,RC4,MD5withRSA,TLSv1,TLSv1.1"
JAVA_OPTIONS="${JAVA_OPTIONS} -Djdk.tls.rejectClientInitiatedRenegotiation=true"
JAVA_OPTIONS="${JAVA_OPTIONS} -Dweblogic.security.SSL.minimumProtocolVersion=TLSv1.2"
JAVA_OPTIONS="${JAVA_OPTIONS} -Dhttps.protocols=TLSv1.2"
JAVA_OPTIONS="${JAVA_OPTIONS} -Djdk.tls.client.protocols=TLSv1.2"
export JAVA_OPTIONS
```

> 注意：在 Java 应用程序中设置环境变量来传递 JVM 参数时，选择使用 _JAVA_OPTIONS、JAVA_OPTIONS，还是 JAVA_OPTS 取决于多个因素，包括你使用的具体 Java 实现、你的应用服务器或框架，以及你的操作系统环境。下面是关于这三个环境变量的详细解释和它们应用的场景：
> 1. _JAVA_OPTIONS
作用: _JAVA_OPTIONS 是一个通用的环境变量，它提供了一种方式来设置所有 Java 应用的 JVM 参数。Oracle JVM 和 OpenJDK 都支持这个变量。
兼容性: 它在大多数标准 JVM 实现中都有效，并且通常会在应用启动时输出被接受的参数，使得它适合用于调试或在全局范围内设置 JVM 选项。
优先级: _JAVA_OPTIONS 中的设置通常覆盖默认的 JVM 配置，但可能会被命令行上直接指定的参数覆盖。
> 2. JAVA_OPTS
作用: JAVA_OPTS 是在很多 Java 应用服务器（如 Tomcat、JBoss 等）和一些脚本中广泛使用的环境变量，用于传递 JVM 参数。
兼容性: 这不是 JVM 官方支持的标准环境变量，而是由特定的应用服务器或脚本使用。例如，Tomcat 的启动脚本 catalina.sh 就会读取 JAVA_OPTS 环境变量并使用其中的参数启动 JVM。
优先级: 在应用服务器或脚本中，JAVA_OPTS 的具体处理方式取决于其实现。通常，这些参数添加到 JVM 启动命令中，可能会被命令行参数覆盖。
> 3. JAVA_OPTIONS
作用: JAVA_OPTIONS 是另一个非标准的环境变量，某些系统和框架使用它来传递 JVM 参数。
兼容性: 与 JAVA_OPTS 类似，JAVA_OPTIONS 的支持完全取决于你的应用服务器或运行环境。它不是由 Oracle 或 OpenJDK 官方支持。
优先级: 类似于 JAVA_OPTS，这些设置被添加到 JVM 命令行中，具体行为取决于它们是如何被应用服务器或脚本处理的。

