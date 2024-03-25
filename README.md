# pySigma udm Backend

This is the Chronicle backend for pySigma. It provides the packages `sigma.backends.chronicle_udm` & `sigma.backends.chronicle_yaral` with the `chronicleBackendUdm` & `chronicleBackendYaral` class respectively.
Further, it contains the following processing pipelines in `sigma.pipelines.chronicle`:

* chronicle_pipeline: Sigma Windows process_create UDM mappings

It supports the following output formats:  

Chronicle UDM  
* default: plain UDM queries

Chronicle YARA-L  
* default: plain YARA-L rules

This backend wouldn't be possible without the great blog [post](https://web.archive.org/web/20230807222337/https://micahbabinski.medium.com/creating-a-sigma-backend-for-fun-and-no-profit-ed16d20da142) by Micah Babinski many thanks as I've ~~stolen~~ borrowed the pipeline logic.  

This backend is currently maintained by:

* [Dylan Shield](https://github.com/ScioShield)