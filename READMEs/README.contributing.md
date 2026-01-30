## Contributing to lws

### How to contribute

Sending a patch with a bug report is very welcome.

For nontrivial problems, it's probably best to discuss on the mailing list,
or on github if you prefer, how to best solve it.

However your contribution is coming is fine:

 - paste a `git diff`

 - send a patch series by mail or mailing list

 - paste in a github issue

 - github PR

are all OK.

### AI usage

So long as the AI is capable and concise, and the code quality is good, it
passes the existing test suites, Coverity etc, AI coproductions with a human
can be fine.

 - You should use your name and email on the patch as the main author.

 - Add a Co-developed-by: header in your patch with a brief description of the
underlying AI, eg, Gemini 3.0 Pro, so we can understand specific advantages
or weaknesses to expect based on the model.

### Coding Standards

Code should look roughly like the existing code, which follows linux kernel
coding style.

If there are non-functional problems I will clean them out when I apply the
patch.

If there are functional problems (eg broken error paths etc) if they are
small compared to the working part I will also clean them.  If there are
larger problems, or consequences to the patch will have to discuss how to
solve them with a retry.

### Funding specific work

If there is a feature you wish was supported in lws, consider paying for the
work to be done.  The maintainer is a consultant and if we can agree the
task, you can quickly get a high quality result that does just what you need,
maintained ongoing along with the rest of lws.

