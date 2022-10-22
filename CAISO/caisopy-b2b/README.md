# caisopy-b2b

## Overview 

caisopy-b2b is a set of commonly used functions for CAISO's SOAP API built with the idea of abstracting away some of the more complicated elements and providing a basis by which developers can build their own tools for interacting with the API.

### Feature Breakdown

#### caisob2blib.py Features
- Automates application of Web Services Security elements to XML payloads
    - Automates signing of XML payloads with your certification
    - Automates adding SOAP elements to XML payload
    - Converts private certification keys to PEM file usable by the API 
- Provides functionality for submitting requests to the API
    - Automates the addition of the CAISO-specific header to XML payloads
    - Recognizes DocAttach vs non-DocAttach distinctions
- Parses responses from server
    - Separates multipart responses into XML and data components
    - Detects error messages in XML and HTML responses and presents them in human-readable format
- Provides additional client-side error reporting

#### caiso-b2b.py Features
- Utilizes and supports the caisob2blib.py library
    - Creates a framework for providing all of the information required by caisob2blib.py
    - Reads that information in through human-readable YAML config files
    - Provides robust client-side error reporting for recognizing any errors in the configuration
    - Receives the response from the server in a data structure that can be passed on to other programs

## API Reference and User Guide

<img src="https://git.caliso.org/tchilton/caisopy-b2b-tchilton/raw/branch/master/samples/diagram2.png">

### Terminology
<details>
<summary>
Click to expand
</summary>
**SOAP:** A messaging protocol for exchanging information in web services using XML

**WSSE/WS-Security:** Web Services Security. An extension of SOAP that applies security to web services.

**B2B:** Business To Business

**PEM and PFX:** Container files that hold your certificate 

**UUE:** A type of encoded file

**YAML:** A human-readable language commonly used for configuration files

**XML:** A markup language much like HTML to structure documents in a way that is machine-readable and human-readable

**MIME:** Multipurpose Internet Mail Extensions. A standard that allows attachments to exist in internet messages
</details>

### Getting Up and Running Starter Guide
<details>
<summary>
Click to expand
</summary>
Here are the steps to get started and up to something like a "hello world" message.

##### 1. Essential B2B Config Fields
Your main configuration file can be named anything, but I reccomend using caiso-b2b-config-example.yml as a basis for getting started.  

The things that need to be changed here are the openssl_path and wsse_config_file. Openssl is installed by default on most Linux distributions and the default path is /usr/bin/openssl. You can test to make sure openssl is installed with the command `openssl version`. Its path can also be found with the command `whereis openssl` and the first result is the path.   

The wsse_config_file field is simply the path to your security config file. There is where you will have your certification information, username, and password.  

It is reccomended that you also have something set for the logfile field. By default it is set to save logs to a file named caiso-b2b.log. This will help you to troubleshoot later on.  

##### 2. Essential Security Config Fields
The example file for this is caiso-b2b-wsse-config-example.yml. The "sibr1" and "cmriRO" parts in the example config are the names of the profiles and can be named whatever you want them to be. These names will be used later back in the main configuration file. The cert_file field is the path to your certification file, and the username and cert_pass are its associated username and password.  

##### 3. Trying it out
First go back to your main configuration file from part 1. Now that our WSSE profile has been defined you can go to the services section and set it in the wsse_profile field of that service. A good service option for our initial test is retrieveRawBidSet_v4 and retrieveRawBidSet_v4_DocAttach.   

If you would like to test these you can change the dates in the request bodies of these services to something more recent. More than likely the date given in the example is too far in the past to retrieve data. The XML elements to look for are <MarketStartTime> and <MarketEndTime>. If MarketEndTime is set to an hour after MarketEndTime on the same date and the date is recent enough then it should work.

After this we can actually try running the program. You will need python so if you're unsure if you have it open a terminal and run `python --version` which should return the version if it is installed. Once you have python you can install the libraries used by this program by running `pip install -r requirements.txt` in the main directory of the program. Pip usually comes with python, but if the previous command fails you can run `python -m pip --version` to make sure it's there, and if it isn't you can run `python -m ensurepip --default-pip` to get it. 

Go to the directory where you have your caisob2b utility and run the following command. The -c section can be omitted if your main configuration file is named b2b.yml, since that is the default.
```shell
python caiso-b2b.py -e mapstage -s retrieveRawBidSet_v4 -c <path to main config file>
```
If everything worked then you should get a 200 response from the server. You can also include the -v flag to get a more detailed output. If you get a 500 response that at least means you reached the server, but more than likely there was something in your request that couldn't be fulfilled. Try changing the dates in the request body to something more recent. The output should look something like this: 

<img src="https://git.caliso.org/tchilton/caisopy-b2b-tchilton/raw/branch/master/samples/BeginnerGuideExample.png" width="800">

</details>

### Command Line Options
<details>
<summary>
Click to expand
</summary>
Run the caiso b2b utility with
```shell
python caiso-b2b.py [options]
```

With the mandatory options the command is:
```shell
python caiso-b2b.py -e <name of environment> [-s <name of service> OR -t] -c <path to main config file> [any other options]
```  
The ordering of the command line options does not matter
<br>

-e --environment:

> Specifies the environment being used. The environment must be listed in your config file and are the sections at CAISO sites where API interaction can be made (e.g. production or MAP stage). This command line option is required.

-c --config_file:

> Specifies the config file, defaults to b2b.yml if omitted

-s --service:

> Specifies the service being called, must be listed in your config file. Either this command line option or the "-t" option must be present.

-b --request_body:

> Specifies a file that contains the request_body. If this option is omitted the request body specified in the config file is used. 

-f --attachment_file:

> Specifies the attachment file to be used. If this option is omitted the attachment file specified in the config file is used. 

-t --test_all:

> Tests every service specified in the config file

-u --unpack_retrieve_attachments:

> If set then uue file responses will be converted to xml

-v --verbose:

> Prints debug information in output

-d --responsedump:

> An alternative to verbose. Instead of printing the debug information throughout you will get a dump of the 'response_dict' object at the end, which contains what response you got as well as the separated UUE and XML data. It can be used in conjunction with verbose too, but you will get repeat information and a lot of output. 
</details>

### Configuration Files
<details>
<summary>
Click to expand
</summary>

#### B2B Services Config
See the example config file "caiso-b2b-config-example.yml" for reference.  
At the top of your config file give the path to openssl on your computer as well as the operating system.  
Optionally a log file can be defined as well where output will be written to.   
These fields must be named:  
```YAML
openssl_path:  
logfile:  
```  
In addition, as a YAML convention the file must start with three hyphens ---

Services must be listed under the services section.  
The services section must start with "services:"  
The necessary components for each listed service are:  
```YAML
<service name>:  
  app:  
  caiso_site:  
  wsse_profile:  
  endpoint:  
  soapaction:  
```
The request_body or attachment_file can be defined here or on the command line.

The caiso_site field is the target site of our API interaction as are listed on the sites page on the CAISO developer website (https://developer.caiso.com) e.g. ADS or Web Services. These need to be defined in the caiso_sites section as is done in the example. Also in this section are the environments that we want to use for each site.

The endpoint field is the portion of the endpoint URL that is not given by the caiso_site field. These endpoint URLs can be found on the CAISO developer website page for the given service. The information for the soapaction field is also given at this page. 

The WSSE profile given in wsse_profile must be one that exists in the wsse_config_file.

#### Building a request_body
The request body must be in the form of XML. The structure of the request body is defined by the XML Schema for that service. These can be found on the page for the given service on the CAISO developer website. They're the .xsd files in the Downloads portion of the page. Looking at the example XML given in the Sample Code section can be useful too. The request_body corresponds to the portion encapsulated by the SOAP envelope body in these examples. 

In addition the caisob2blib.py library provides a few macros that can be used in request bodies.  
Using "TRADE_DATE_TODAY", "TRADE_DATE_TOMORROW", or "TRADE_DATE_YESTERDAY" in place of a date in a request body will result in them being replaced by their corresponding dates at runtime.

Some example request bodies can be found in the provided example configuration file and in the request_bodies folder. You can also set up requests using the SOAP UI tool to see more examples of how these are set up. 

In your configuration file you can either define the whole request_body within its field, or you can define a path to a file that contains the request body.

#### Security Config
See the example config file "caiso-b2b-wsse-config-example.yml" for reference.

The security configuration file must start with "wsse_profiles:"  
The necessary components for each listed WSSE profile are:  
```YAML
<profile name>:  
  username:  
  cert_file:  
  cert_pass:  
```
</details>

### DocAttach vs non-DocAttach
Responses in non-DocAttach retrieve requests have a multipart response following the MIME specification with a boundary separating the XML portion from the UUE portion (see: https://www.w3.org/TR/SOAP-attachments/)  
Responses in DocAttach retrieve requests have the UUE data inside of the SOAP envelope.  
In submit requests the same is true but for the submission that is being sent.

This distinction and its effects on the submission/response are recognized and handled automatically by caisob2blib.py


### Logging
A log file can be created that stores the output of the program by setting a "logfile" field in your configuration file. This field in on the same hierarchial level as openssl_path, caiso_sites, and services.

## Helpful URL's
**CAISO Developer Website**  
https://developer.caiso.com/  

**XML Security Documentation**  
https://www.w3.org/TR/xmldsig-core/  

**WS-Security (WSSE)**  
https://www.oracle.com/topics/technologies/ws-audit-authentication.html  
https://www.ibm.com/docs/en/app-connect/11.0.0?topic=security-ws  

**SOAP with MIME**  
https://www.w3.org/TR/SOAP-attachments/

## Cloning the repository

```shell
git clone https://git.caliso.org/CAISO/caisopy-b2b 
```
