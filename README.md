# 2021-2022秋季学期，网络安全

## 实验报告要求

* Markdown 书写，且在 Github 上渲染出的排版效果正常，可读性强；
* 在 Github 上每次提交作业单独从 `master` 分支 **新** 开一个分支；
    * 每次作业均保存到 **独立不冲突** 的子目录；
* 图文并茂证明：
    * 实验关键步骤是自己做的；
    * **哪些** 实验结果符合实验要求预期；
* 如有涉及到代码、配置文件，请记得 `commit` **源代码** 文件；
* 规范的 Git 工作流程：
    * **提交作业等待批改**：提交 `PR` 请求将作业分支合并到 `master` 分支；
        * 未 `PR` 时的 `commit` 不会被批改；
    * 课程没有在教务处系统上查到分数之前，**禁止合并或关闭** 已有批改记录的 `PR`，可以在该 `PR` 对应的分支上继续提交新变更；；
    * 每次实验报告只保留一个 `Open` 状态的 `PR` ，禁止同一次作业发起多个 `PR`；
    * `PR` 的标题应体现本次实验报告的主题；

> 示例作业目录（所有分支合并到 master 分支后状态）如下：

```bash
.
├── .gitattributes
├── .gitignore
├── README.md
├── chap0x01
│   ├── README.md
│   └── img
│       ├── vb-setup.png
│       └── vb-victim-screenshot-1.png
├── chap0x02
│   └── README.md
├── chap0x03
│   └── README.md
├── chap0x04
│   └── README.md
└── chap0x05
    ├── README.md
    └── code
        ├── exp.py
        └── nginx.conf
```

> 示例 Git 分支结构如下：

![](https://c4pr1c3.github.io/cuc-ns/chap0x01/attach/chap0x01/media/forks.png)
