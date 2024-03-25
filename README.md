# pySigma udm Backend

This is the Chronicle backend for pySigma. It provides the package `sigma.backends.chronicle_udm` & `sigma.backends.chronicle_yaral` with the `chronicleBackendUdm` & `chronicleBackendYaral` class respectively.
Further, it contains the following processing pipelines in `sigma.pipelines.chronicle`:

* chronicle_pipeline: Sigma Windows process_create UDM mappings

It supports the following output formats:  

Chronicle UDM  
* default: plain udm queries
Chronicle YARA-L  
* default: plain YARA-L rules


This backend is currently maintained by:

* [Dylan Shield](https://github.com/ScioShield)
* [Thomas Patzke](https://github.com/SigmaHQ/)