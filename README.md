[![License](https://img.shields.io/github/license/Torchmind/Authenticator.svg?style=flat-square)](https://www.apache.org/licenses/LICENSE-2.0.txt)
[![Maven Central](https://img.shields.io/maven-central/v/com.torchmind/authenticator.svg?style=flat-square)](https://search.maven.org/#search%7Cga%7C1%7Cg%3Acom.torchmind%20a%3Aauthenticator)
[![GitHub Release](https://img.shields.io/github/release/Torchmind/Authenticator.svg?style=flat-square)](https://github.com/Torchmind/Authenticator/releases)
[![CircleCI](https://img.shields.io/circleci/project/github/Torchmind/Authenticator.svg?style=flat-square)](https://circleci.com/gh/Torchmind/Authenticator)

Authenticator
=============

Table of Contents
-----------------
* [About](#about)
* [Contacts](#contacts)
* [Usage](#usage)
* [License](#license)
* [Downloads](#downloads)
* [Issues](#issues)
* [Building](#building)
* [Contributing](#contributing)

About
-----

Lightweight Java implementations of the HOTP and TOTP specifications for writing multi-factor
authentication providers in Java.

Contacts
--------

* [Website](https://www.torchmind.com/open-source)
* [IRC #Torchmind on Freenode](http://webchat.freenode.net/?channels=%23Torchmind)
* [GitHub](https://github.com/Torchmind/Authenticator)

Usage
-----

Authenticator is available via the maven central repository and thus you may directly specify it as a dependency in your
maven project configuration:

```xml
<dependency>
        <groupId>com.torchmind</groupId>
        <artifactId>authenticator</artifactId>
        <version>1.1.0</version>
</dependency>
```

If you do however require an unstable revision of the library you will need to add the Sonatype snapshot repository to
the list of your repositories as maven central does not ship unstable versions:

```xml
<repository>
        <id>sonatype</id>
        <name>Sonatype Open Source Repository</name>
        <url>https://oss.sonatype.org/content/repositories/snapshots</url>

        <snapshots>
                <enabled>true</enabled>
        </snapshots>
</repository>
```

License
-------

Copyright (C) 2016 Johannes "Akkarin" Donath and other copyright owners as documented in the project's IP log.
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](https://www.apache.org/licenses/LICENSE-2.0.txt)

Downloads
---------

Released versions of the library can be found on [GitHub](https://github.com/Torchmind/Authenticator/releases).

Issues
------

You encountered problems with the library or have a suggestion? Create an issue!

1. Make sure your issue has not been fixed in a newer version (check the list of [closed issues](https://github.com/Torchmind/Authenticator/issues?q=is%3Aissue+is%3Aclosed)
1. Create [a new issue](https://github.com/Torchmind/Authenticator/issues/new) from the [issues page](https://github.com/Torchmind/Authenticator/issues)
1. Enter your issue's title (something that summarizes your issue) and create a detailed description containing:
   - What is the expected result?
   - What problem occurs?
   - How to reproduce the problem?
   - Crash Log (Please use a [Pastebin](http://www.pastebin.com) service)
1. Click "Submit" and wait for further instructions

Building
--------

1. Clone this repository via ```git clone https://github.com/Torchmind/Authenticator.git``` or download a [zip](https://github.com/Torchmind/Authenticator/archive/master.zip)
1. Build the modification by running ```mvn clean install```
1. The resulting jars can be found in their respective ```target``` directories as well as your local maven repository

Contributing
------------

Before you add any major changes to the library you may want to discuss them with us (see [Contact](#contact)) as
we may choose to reject your changes for various reasons. All contributions are applied via [Pull-Requests](https://help.github.com/articles/creating-a-pull-request).
Patches will not be accepted. Also be aware that all of your contributions are made available under the terms of the
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0.txt). Please read the [Contribution Guidelines](CONTRIBUTING.md)
for more information.
