# Mango

![](https://github.com/SxNade/Mango/blob/main/mango.png)

**Mango is a user interactive Powershell program to search for possible privilege escalation vectors on windows** 


# Installing and Running

*For repo*

      $ git clone https://github.com/SxNade/Mango
      $ cd Mango
      
      $ ls -la

**Download with curl one liner**

      curl https://raw.githubusercontent.com/SxNade/Mango/main/mango.ps1 -o mango.ps1

**Execute from command-prompt**

```
powershell.exe -c  "./mango.ps1"
```

# About

This script is kept very minimalistic for now, more code would added in upcoming updates!
The functionallity of script is Designed in a way that all checks Requested by user are performed as Fast as Possbile.
The script manages and executed multiple checks in the background at the same time and then retrieves the command Output for each thread.
Also The script would not crash your shell even in case of overwhelming output [as for now ;)].

