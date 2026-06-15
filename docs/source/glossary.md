# Glossary #

```{glossary}

Backend
    The backend is the server-side component of an application.
    Typically, it responds to requests form the {term}`frontend`.
    The backend is typically where the data processing is done.

Container
    Containers are a form of operating system virtualization.
    A single container holds all necessary configurations, executables,
    and libraries. They can be an entire project or a small microservice.
    Popular tools are {term}`Docker` and {term}`Podman`.

Containerization
    The process of leveraging a {term}`Docker` or {term}`Podman` {term}`container`
    for system virtualization and sandboxing.

Docker
    Docker is a system for building and running {term}`containers <container>`.
    Docker uses OS-level virtualization to deliver
    software in packages called {term}`containers <container>`.
    Containers are generally isolated from one another. Similar to
    {term}`Podman`.

eleVADR
    eleVADR is a network security analysis engine designed to assess
    {term}`Operational Technology`
    (OT) systems by transforming raw {term}`PCAP` traffic into
    actionable security intelligence.

Frontend
    A frontend is a user interface for a system. Typically this is used
    in web development to refer to the series
    of web pages that a user interacts with. Typically, the front end
    is provided as convenience to interface with
    the {term}`backend`.

ICS
    Industrial Control System(s).

JSON
    JavaScript Object Notation. It is a machine readable data format.
    Read more [JSON](https://www.json.org/json-en.html)

Numpy
    Numpy is the primary library for scientific computing in {term}`Python`
    providing efficient support for large, multi-dimensional
    arrays and matrices. It also provides a large collection of high-level mathematical
    functions. Read more [numpy](https://numpy.org)

OT
Operational Technology
    Umbrella term for technology that run critical operations, including {term}`ICS`
    and Building Automation Systems.

Pandas
    Pandas is a {term}`Python` data analysis and manipulation tool providing fast,
    flexible, and expressive data structures designed to make working with structured
    and relational data easy. Read more [pandas](https://pandas.pydata.org)

PCAP
    Packet Capture. Used as both a term for capturing network traffic or to the
    ``.pcap`` and ``.pcapng`` file formats.

Podman
    A system for building and running {term}`containers <container>`. Podman
    is operated by Red Hat. Similar to {term}`Docker`.

Python
    The Python programming language. This is the language the {term}`backend`
    of {term}`eleVADR` is written in.

React
    A JavaScript library for building web and native user interfaces from components.
    Read more [React](https://react.dev)

Zat
    Zat is a python package that supports the processing and analysis
    of {term}`Zeek` data with `Pandas` and more.
    Read more [zat](https://github.com/SuperCowPowers/zat)

Zeek
    An open source network security monitoring tool. It analyzes
    network data including {term}`PCAP` and
    parses it into a series of logs. It is extensible as well.
    Read more [Zeek](https://zeek.org)
```
