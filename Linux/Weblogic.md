# Weblogic

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

##  Weblogic 定时修改密码

### 0x01 寻找 resetUserPassword 方法

1. 按照以下步骤，基本上就可以找到 resetUserPassword 方法。

```shell
# 打开 wlst 工具
[oracle@8ffd4daff884 ~]$ ./weblogic/wlserver/common/bin/wlst.sh
## 连接 Weblogic
wls:/offline> connect('weblogic', 'welcome1', 't3://localhost:7001')
## 切换位置
wls:/offline> cd('/SecurityConfiguration/base_domain/Realms/myrealm/AuthenticationProviders/DefaultAuthenticator')
## 列出 MBean
wls:/offline> ls()
dr--   Realm

-r--   ControlFlag                                  REQUIRED
-r--   Description                                  WebLogic Authentication Provider
-r--   EnableGroupMembershipLookupHierarchyCaching  true
-r--   GroupHierarchyCacheTTL                       60
-r--   GroupMembershipSearching                     unlimited
-r--   KeepAliveEnabled                             false
-r--   MaxGroupHierarchiesInCache                   100
-r--   MaxGroupMembershipSearchLevel                0
-r--   MinimumPasswordLength                        8
-r--   Name                                         DefaultAuthenticator
-r--   PasswordDigestEnabled                        false
-r--   PropagateCauseForLoginException              false
-r--   ProviderClassName                            weblogic.security.providers.authentication.DefaultAuthenticationProviderImpl
-r--   SupportedExportConstraints                   java.lang.String[users, groups, passwords]
-r--   SupportedExportFormats                       java.lang.String[DefaultAtn]
-r--   SupportedImportConstraints                   java.lang.String[]
-r--   SupportedImportFormats                       java.lang.String[DefaultAtn]
-r--   SupportedUserAttributeNames                  java.lang.String[displayname, employeenumber, employeetype, givenname, homephone, mail, title, preferredlanguage, departmentnumber, facsimiletelephonenumber, mobile, pager, telephonenumber, postaladdress, street, l, st, postofficebox, c, homepostaladdress]
-r--   UseRetrievedUserNameAsPrincipal              false
-r--   Version                                      1.0

-r-x   addMemberToGroup                             Void : String(groupName),String(memberUserOrGroupName)
-r-x   advance                                      Void : String(cursor)
-r-x   changeUserPassword                           Void : String(userName),String(oldPassword),String(newPassword)
-r-x   close                                        Void : String(cursor)
-r-x   exportData                                   Void : String(format),String(filename),java.util.Properties
-r-x   getCurrentName                               String : String(cursor)
-r-x   getGroupDescription                          String : String(groupName)
-r-x   getSupportedUserAttributeType                javax.management.openmbean.OpenType : String(User)
-r-x   getUserAttributeValue                        Object : String(userName),String(userAttributeName)
-r-x   getUserDescription                           String : String(userName)
-r-x   groupExists                                  Boolean : String(groupName)
-r-x   haveCurrent                                  Boolean : String(cursor)
-r-x   importData                                   Void : String(format),String(filename),java.util.Properties
-r-x   isMember                                     Boolean : String(parentGroupName),String(memberUserOrGroupName),Boolean(recursive)
-r-x   isSet                                        Boolean : String(propertyName)
-r-x   isUserAttributeNameSupported                 Boolean : String(User)
-r-x   listAllUsersInGroup                          String[] : String(groupName),String(userNameWildcard),Integer(maximumToReturn)
-r-x   listGroupMembers                             String : String(groupName),String(memberUserOrGroupNameWildcard),Integer(maximumToReturn)
-r-x   listGroups                                   String : String(groupNameWildcard),Integer(maximumToReturn)
-r-x   listMemberGroups                             String : String(memberUserOrGroupName)
-r-x   listUsers                                    String : String(userNameWildcard),Integer(maximumToReturn)
-r-x   removeGroup                                  Void : String(groupName)
-r-x   removeMemberFromGroup                        Void : String(groupName),String(memberUserOrGroupName)
-r-x   removeUser                                   Void : String(userName)
-r-x   resetUserPassword                            Void : String(userName),String(newPassword)
-r-x   setGroupDescription                          Void : String(groupName),String(description)
-r-x   setUserAttributeValue                        Void : String(userName),String(userAttributeName),Object(newValue)
-r-x   setUserDescription                           Void : String(userName),String(description)
-r-x   unSet                                        Void : String(propertyName)
-r-x   userExists                                   Boolean : String(userName)
-r-x   wls_getDisplayName                           String : 
```

### 0x02 编写脚本并设置定时任务

~~1. 在 wlst.sh 所在目录添加脚本 change_weblogic_password.py~~

不建议使用以下脚本：
- 没有对密码加密直接明文存储服务器中
- 修改后，貌似没有将密码同步至登录凭证存储文件中，导致重启后只能使用旧的 weblogic 密码登录

```python
import random
import string
import subprocess
import os

def get_weblogic_current_password():
    with open("./weblogic_password_change_logs","r") as fs:
        current_password = fs.readlines()[-1]
        print("current_password: " + current_password)
        return current_password

def generate_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

current_password = get_weblogic_current_password()
new_password = generate_password(12)

with open("./weblogic_password_change_logs","a") as fs:
    fs.write(new_password + '\n')

wlst_script_comment = '''
connect('weblogic', %s, 't3://localhost:7001')
cd('/SecurityConfiguration/base_domain/Realms/myrealm/AuthenticationProviders/DefaultAuthenticator')
cmo.resetUserPassword('weblogic', %s)
disconnect()
exit()
''' % (current_password,new_password)

with open("./wlst_script_comment_temp","w") as fs:
    fs.write(wlst_script_comment)

# 命令和参数
command = './wlst.sh'
args = './wlst_script_comment_temp'

# 完整命令列表
cmd = [command, args]

# 启动进程
process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# 等待命令执行完成并获取输出
output, errors = process.communicate()

# 检查命令是否成功执行
if process.returncode == 0:
    print("Command executed successfully!")
else:
    print("Error executing command")

# 删除临时文件
if os.path.exists(args):
    os.remove(args)
    print("Del " + args + "successfully!")
```

2. 设置定时任务,每两个月执行一次
   
```shell
0 0 1 */2 * /usr/bin/python /path/to/your/change_weblogic_password.py
```