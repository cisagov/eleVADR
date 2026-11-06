# Introduction #

{term}`eleVADR` is a network security analysis engine
designed to assess {term}`Operational Technology`
(OT) systems by transforming raw {term}`PCAP` traffic into
actionable security intelligence.

The overall goal is to support the automated analysis of data to
allow anyone operating {term}`OT` to make informed decisions about
their network security posture.

It is currently designed with ease of use in mind by leveraging
{term}`containerization`.

## Core Architecture ##

EleVADR is split into a {term}`frontend` and a {term}`backend`
component.

### Backend ###

The backend is a {term}`Python` application that is used to run
{term}`Zeek` to collect network data, compile it against a
Detection Context profile, and run it through a registry of
75 detector modules to generate a {term}`JSON` report of findings.

### Frontend ###

The frontend is a {term}`React` application that is used to interact
with the {term}`Python` {term}`backend` component.
The frontend takes the {term}`JSON` report that the {term}`backend`
generates and displays it in an interactive format,
allowing the user to filter and drill-down into the data.

The frontend is organized into sections that mirror what the {term}`backend` generates.

#### Upload Form ####

The upload form is where a user can upload a {term}`PCAP` to run the analysis
and download the associated JSON report.
There is also an option to upload a {term}`JSON` report to view it.

#### Report ####

The frontend is a {term}`React` application that is used to interact with the
{term}`Python` {term}`backend` component.
The frontend takes the {term}`JSON` report that the {term}`backend`
generates and displays it in an interactive format,
allowing the user to filter and drill-down into the data.

The frontend is organized into the following sections.

##### Executive Summary #####

The executive summary is a high-level set of key takeaways from the report.

(report-modules)=

##### Report Modules #####

The report's findings come from a registry of 75 detector modules,
each targeting a specific analytic question (e.g. suspicious outbound
connections, cross-segment OT traffic, service exposure).
