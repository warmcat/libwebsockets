# Heading *one* #

Paragraph with **strong**, *em*, `code`, [link](http://x/y?a=b&c=d "t"),
![img](img.png), <http://auto.link>, https://bare.auto/link and \*escaped\*.
Continued line with a http://x/ inside [![alt](i.png)](http://l) here.

> quoted paragraph
> > nested quote
> - list in quote
>
> after blank

- bullet one
- bullet two
  continued
  * nested bullet

1. first
2. second
10. tenth

| a | b |
|---|:-:|
| 1 | 2 \| pipe |
| 3 |

not | a table

    indented code
    more code

```c
#include <stdio.h>
int main(void) { return 0; /* c */ }
```

~~~diff
--- a/f
+++ b/f
@@ -1 +1 @@
-old
+new
~~~

````
```
nested fence chars
````

***

```
unterminated fence at end /
