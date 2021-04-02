# PAPAS, the PArameter Pollution Analysis System

Years back, we investigated the prevalence in-the-wild of a new class of web threat named as HTTP Parameter Pollution (HPP) vulnerability.

To this need, we developed PAPAS i.e. an automated testing framework that rely on a custom Firefox's extension to load and render dynamic web pages and of a Python 2.7 engine for testing whether such web page either vulnerable or exploitable to HPP.

Years after I decided to make this code public under GPL license, and this repository serves to this matter.

The repository is organized as follow:

- [engine](engine/) contains the code responsable for fetching the web pages to be tested and to verify whether such pages are a vulnerable target and could be potentially exploited

- [plugin](plugin/) contains the Firefox's plugin requested to make PAPAS working as expected. The plugin communicates with the engine via a network socket in order to fetch the commands and return the content of the pages.

- [doc](doc/) contains the paper we published at NDSS 2011 and the presentation given at Black Hat USA 2011.

For anything else, don't hesitate to contact me.

*Marco*
