## 常用命令

**3. git add**
  - 作用: 将文件更改添加到暂存区。
  - 用法: git add [file] 或 git add .（添加所有更改的文件）

**4. git commit**
  - 作用: 提交暂存区的更改到仓库历史中。
  - 用法: git commit -m "commit message"
  - 示例: git commit -m "Initial commit"

**5. git status**
  - 作用: 显示工作目录和暂存区的状态。
  - 用法: git status

**6. git push**
  - 作用: 将本地分支的更新推送到远程仓库。
  - 用法: git push [remote] [branch]
  - 示例: git push origin master

**7. git pull**
  - 作用: 从远程仓库获取最新版本并合并到本地。
  - 用法: git pull [remote] [branch]
  - 示例: git pull origin master

**8. git branch**
  - 作用: 管理分支。
  - 用法:
    - 查看分支: git branch
    - 创建分支: git branch [branch_name]
    - 删除分支: git branch -d [branch_name]

**9. git checkout**
  - 作用: 切换分支或恢复工作树文件。
  - 用法:
    - 切换分支: git checkout [branch_name]
    - 创建并切换到新分支: git checkout -b [new_branch]

**10. git merge**
  - 作用: 将两个或多个开发历史合并成一条线。
  - 用法: git merge [branch]
  - 示例: 合并 feature 分支到当前分支: git merge feature

**11. git revert**
  - 作用: 撤销之前的提交。
  - 用法: git revert [commit]

**12. git log**
  - 作用: 显示提交历史记录。
  - 用法: git log
  - 选项:
    - --oneline: 简洁显示每个提交的信息。
    - --graph: 以图形方式显示分支、合并历史。

**13. git diff**
  - 作用: 显示工作目录和暂存区、或两个提交之间的差异。
  - 用法: git diff（未暂存的更改）或 git diff --staged（暂存的更改）

**14. git rm**
  - 作用: 从工作区和索引中删除文件。
  - 用法: git rm [file]


**15. git tag**
  - 作用: 用于标记特定的提交作为重要的里程碑，例如发布版本。
  - 用法:
    - 创建轻量标签: git tag [tagname]
    - 创建带有附加信息的注释标签: git tag -a [tagname] -m "message"

**16. git fetch**
  - 作用: 从远程仓库下载最新的历史数据，但不进行合并或重写当前工作。
  - 用法: git fetch [remote]

**17. git blame**
  - 作用: 显示指定文件每一行的最后修改人，帮助找出谁做了哪些更改。
  - 用法: git blame [file]

## 从初始源仓库更新并合并内容
```shell
# 切换到你的项目目录
cd path/to/your/fork

# 添加原始仓库为一个新的远程源，命名为 'upstream'
git remote add upstream https://github.com/original-owner/original-repository.git

# 拉取 upstream 的数据
git fetch upstream

# 切换到主分支，这里假设是 'master'
git checkout master

# 将 upstream/master 合并到你的本地主分支
git merge upstream/master

# 将更改推送到你的 GitHub fork
git push origin master

```

## 删除指定分支

```shell
# 删除本地分支
git branch -d feature
# 删除远程分支
git push origin --delete feature
```

## 新建分支

```shell
# 新建分支并切换
git checkout -b hea

# 添加到缓存
git add .

# 提交更改
git commit -m "Describe the changes you made"
```

## 配置 ssh 密钥
1. 生成 SSH 密钥: 如果你还没有 SSH 密钥，可以在终端中运行以下命令生成一个：
```shell
ssh-keygen -t ed25519 -C "xx@gmail.com"
```

2. 添加 SSH 密钥到 GitHub:
   1. 将生成的公钥（默认位于 ~/.ssh/id_ed25519.pub）添加到 GitHub。
   2. 进入 Settings（设置）> SSH and GPG keys（SSH 和 GPG 密钥）> New SSH key（新的 SSH 密钥）。
   3. 输入一个描述性的标题，粘贴你的公钥内容，点击 “Add SSH key”（添加 SSH 密钥）。

3. 使用 SSH 克隆和推送: 确保你的仓库的远程 URL 使用 SSH 而非 HTTPS。你可以通过以下命令查看和修改当前仓库的远程 URL：
```shell
git remote -v
git remote set-url origin git@github.com:xx/hacktricks.git
```

## 检查文件历史修改记录

### 1. git log
这个命令用来查看一个文件的提交历史。你可以看到每次提交的详细信息，包括提交者、日期和提交信息。

```shell
git log -- path/to/file
```

这将列出所有涉及指定文件的提交。如果你想看到文件在每次提交时的具体变化，可以加上 -p 选项：

```shell
git log -p -- path/to/file
```

这会显示每个提交的差异（diff），即每次提交具体修改了哪些内容。

### 2. git blame
这个命令用于显示每一行代码是谁在什么时间提交的，非常适合追踪文件的行级更改历史：

```shell
git blame path/to/file
```

git blame 显示的输出中会包括提交哈希、作者、日期和行内容。

### 3. git diff
如果你想比较文件在两个不同提交或分支之间的差异，可以使用 git diff 命令。例如，比较文件在当前分支和另一个分支上的差异：

```shell
git diff branch1 branch2 -- path/to/file
```

或者比较文件在两个不同提交中的差异：

```shell
git diff commit1 commit2 -- path/to/file
```
### 4. git show
如果你知道特定的提交哈希，并想查看该提交中对文件的更改，可以使用：

```shell
git show commit_hash -- path/to/file
```

这将显示那次提交中对指定文件的具体更改。