# PAPAS, the PArameter Pollution Analysis System

Years back, we investigated the prevalence in-the-wild of a new class of web vulnerability named HTTP Parameter Pollution (HPP).

To this need, we developed PAPAS i.e. an automated testing framework that relies on a custom Firefox's extension to load and render dynamic web pages, and oo a Python 2.7 engine for testing whether such web page are either vulnerable or exploitable to HPP.

Years after, I decided to make all this code public under GPLv3 license, and this repository serves to this matter.

The repository is organized as follow:

- [engine](engine/) contains the code responsible for fetching the web pages to be tested and for verifying whether such pages are a vulnerable target or could be potentially exploited

- [plugin](plugin/) contains the Firefox's plugin needed to make PAPAS working as expected. The plugin communicates with the engine via a network socket i.e. in order to fetch the commands and to return the content of the pages.

- [doc](doc/) contains the paper that we published at NDSS 2011 and the presentation given at Black Hat USA 2011.

For anything else, don't hesitate to contact me.

*Marco*
