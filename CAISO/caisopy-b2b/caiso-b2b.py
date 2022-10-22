############################################################################
# JOHN HUETTER, THOMAS CHILTON CALIFORNIA ISO
# 20200320
############################################################################

############################################################################
# Disclaimer of Warranty
# The CAISO API is provided “as is” and CAISO disclaims all warranties, conditions, or representations
# (express, implied, oral or written) with respect to the CAISO API and any support related thereto,
# including all warranties of merchantability, compatibility, fitness for a particular purpose,
# non-infringement, non-interference, accuracy of data, and warranties arising from a course of dealing.
# For further information, see CAISO Privacy Notice and Terms of Use
# (http://www.caiso.com/Pages/PrivacyPolicy.aspx ).
############################################################################

# import datetime
import logging
import os
import pprint
import sys
import tempfile
from logging import StreamHandler
from logging.handlers import RotatingFileHandler
from optparse import OptionParser

import yaml

import caisopy_b2b

# caisopy_b2b is a module containing one file: caisob2blib.py


# ----------------------------------------------------------------------------------------------------
def initLogging():

    try:

        # Set up logger
        logger = logging.getLogger("caiso-b2b")
        logger.setLevel(logging.INFO)

        # create formatter and add it to the handlers
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)5s - %(message)s", "%Y-%m-%d %H:%M:%S"
        )

        # Set up a rotating log
        # Create a rotating log file with retention of 10MB and 3 rotations
        # Only do if we have logfile in the config
        if "logfile" in b2b_config_dict:
            logfile_handler = RotatingFileHandler(
                b2b_config_dict["logfile"], maxBytes=1024 * 1024 * 50, backupCount=3
            )
            logfile_handler.setFormatter(formatter)
            logger.addHandler(logfile_handler)
        else:
            print("No logfile defined, output will just be in the console")
        # Log everything to the screen also
        # If verbose we set to DEBUG back in main
        stream_handler = StreamHandler()
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

        return logger

    except Exception as err:
        print(err)
        raise Exception(
            "CAISO-601: Exception raised while initializing logger"
        ) from err


# ----------------------------------------------------------------------------------------------------
def argParser():

    # Parse command line arguments

    try:

        parser = OptionParser()
        parser.add_option(
            "-e",
            "--environment",
            dest="environment",
            type="str",
            action="store",
            help="Specifies environment being used. This is a required option.",
        )
        parser.add_option(
            "-c",
            "--config_file",
            dest="config_file",
            type="str",
            action="store",
            default="b2b.yml",
            help="Specifies the configuration file. This is a required option.",
        )
        parser.add_option(
            "-s",
            "--service",
            dest="service",
            type="str",
            action="store",
            help="Specifies the service being called. This or -t has to be present.",
        )
        parser.add_option(
            "-b",
            "--request_body",
            dest="request_body",
            type="str",
            action="store",
            help="Takes in the request body as a string from the command line. "
            + "If not set the one in your config will be used",
        )
        parser.add_option(
            "-f",
            "--attachment_file",
            dest="attachment_file",
            type="str",
            action="store",
            help="Specifies the attachment file to be used. If not set the "
            + "one in your config will be used",
        )
        parser.add_option(
            "-t",
            "--test_all",
            action="store_true",
            dest="test_all",
            help="If set then every service specified in the config file will "
            + "be executed. This or -s must be present",
        )
        parser.add_option(
            "-u",
            "--unpack_retrieve_attachments",
            action="store_true",
            dest="unpack_retrieve_attachments",
            help="If set then uue data responses will be converted to xml",
        )
        parser.add_option(
            "-v",
            "--verbose",
            action="store_true",
            dest="verbose",
            help="Prints debug information in output",
        )
        parser.add_option(
            "-d",
            "--responsedump",
            action="store_true",
            dest="responsedump",
            help="An alternative to verbose. Instead of printing the debug "
            + "information throughout you will get a dump of the "
            + "'response_dict' object at the end, which contains what response "
            + "you got as well as UUE and XML attachments. Can be used in "
            + "conjunction with verbose too, but you will get some repeat "
            + "information and a lot of output",
        )
        options, remainder = parser.parse_args()

        usage_problem = False

        if options.test_all is None and options.service is None:
            usage_problem = True
            print("Please provide either -t, OR -s <service>")

        if options.environment is None:
            usage_problem = True
            print("Please provide -e <environment>")

        if usage_problem is True:
            parser.print_help()
            sys.exit(1)

        return options

    except Exception as err:
        raise Exception(
            "CAISO-600: Exception raised while parsing command line options"
        ) from err
        return None


# ----------------------------------------------------------------------------------------------------
def topLevelChecks(b2b_config_dict, b2b_wsse_config_dict, problem_detected):

    # Configuration Checking: Making sure all these sections are there
    # Check for caiso_sites section
    if "caiso_sites" not in b2b_config_dict or b2b_config_dict["caiso_sites"] is None:
        problem_detected = True
        log.error(
            "CAISO-110: No caiso_sites section found in "
            + "main config file or section is empty"
        )
    # Check for openssl_path field
    if "openssl_path" not in b2b_config_dict or b2b_config_dict["openssl_path"] is None:
        problem_detected = True
        log.error("CAISO-111: No openssl_path defined in " + "main config file")
    # Check for wsse_profiles section in wsse config
    if (
        "wsse_profiles" not in b2b_wsse_config_dict
        or b2b_wsse_config_dict["wsse_profiles"] is None
    ):
        problem_detected = True
        log.error(
            "CAISO-117: No wsse_profiles section found in "
            + b2b_config_dict["wsse_config_file"]
            + " or section is empty"
        )

    return problem_detected


# ----------------------------------------------------------------------------------------------------
def endpointChecks(b2b_config_dict, environment, service, b2b, problem_detected):

    # Resolve the endpoint
    # Check for caiso_site in service
    if (
        "caiso_site" in b2b_config_dict["services"][service]
        and b2b_config_dict["services"][service]["caiso_site"] is not None
    ):
        caiso_site = b2b_config_dict["services"][service]["caiso_site"]
        # Check for caiso_site in caiso_sites section
        if (
            caiso_site in b2b_config_dict["caiso_sites"]
            and b2b_config_dict["caiso_sites"][caiso_site] is not None
        ):
            # Check for environment in caiso_site in caiso_sites section
            if (
                opts.environment in b2b_config_dict["caiso_sites"][caiso_site]
                and b2b_config_dict["caiso_sites"][caiso_site][environment] is not None
                and "endpoint" in b2b_config_dict["services"][service]
                and b2b_config_dict["services"][service]["endpoint"] is not None
            ):
                b2b.endpoint = (
                    b2b_config_dict["caiso_sites"][caiso_site][environment]
                    + "/"
                    + b2b_config_dict["services"][service]["endpoint"]
                )
            else:
                problem_detected = True
                log.error(
                    "CAISO-103: Either no environment field has been defined matching name '"
                    + environment
                    + "' for caiso_site '"
                    + caiso_site
                    + "'"
                )
                log.error(
                    "CAISO-103: Or there is no endpoint field defined for service "
                    + service
                )
        else:
            problem_detected = True
            log.error(
                "CAISO-102: Either caiso_site '"
                + caiso_site
                + "' has not been found in the caiso_sites section in"
                + " the main configuration file"
            )
            log.error(
                "CAISO-102: Or the section for '"
                + caiso_site
                + "' has no listed environments"
            )
    else:
        problem_detected = True
        log.error(
            "CAISO-101: No caiso_site defined for service "
            + service
            + " found in config"
        )

    return problem_detected


# ----------------------------------------------------------------------------------------------------
def wsseChecks(b2b_config_dict, b2b_wsse_config_dict, service, b2b, problem_detected):

    # WSSE Profile Information Grabbing
    # Check for wsse_profile in service
    if (
        "wsse_profile" in b2b_config_dict["services"][service]
        and b2b_config_dict["services"][service]["wsse_profile"] is not None
    ):
        wsse_profile = b2b_config_dict["services"][service]["wsse_profile"]

        # Check for wsse_profile in WSSE config file wsse_profiles section
        if (
            wsse_profile in b2b_wsse_config_dict["wsse_profiles"]
            and b2b_wsse_config_dict["wsse_profiles"][wsse_profile] is not None
        ):
            # Check for username field
            if (
                "username" in b2b_wsse_config_dict["wsse_profiles"][wsse_profile]
                and b2b_wsse_config_dict["wsse_profiles"][wsse_profile]["username"]
                is not None
            ):
                b2b.username = b2b_wsse_config_dict["wsse_profiles"][wsse_profile][
                    "username"
                ]
            else:
                problem_detected = True
                log.error(
                    "CAISO-118: No username field found for profile '"
                    + wsse_profile
                    + "' in file "
                    + b2b_config_dict["wsse_config_file"]
                    + " either it doesn't exist or the field is empty."
                )
            # Getting Certification File
            # Check for cert_pass field
            if (
                "cert_pass" in b2b_wsse_config_dict["wsse_profiles"][wsse_profile]
                or b2b_wsse_config_dict["wsse_profiles"][wsse_profile]["cert_pass"]
                is not None
            ):
                b2b.private_key_pass = b2b_wsse_config_dict["wsse_profiles"][
                    wsse_profile
                ]["cert_pass"]
            else:
                problem_detected = True
                log.error(
                    "CAISO-116: No cert_pass field found for profile '"
                    + wsse_profile
                    + "' in "
                    + b2b_config_dict["wsse_config_file"]
                    + " either it doesn't exist or the field is empty."
                )
            # Check for cert_file field
            if (
                "cert_file" in b2b_wsse_config_dict["wsse_profiles"][wsse_profile]
                and b2b_wsse_config_dict["wsse_profiles"][wsse_profile]["cert_file"]
                is not None
            ):
                if (
                    ".pem"
                    in b2b_wsse_config_dict["wsse_profiles"][wsse_profile]["cert_file"]
                ):
                    b2b.private_key_pem_filename = b2b_wsse_config_dict[
                        "wsse_profiles"
                    ][wsse_profile]["cert_file"]
                    b2b.issuing_pem_filename = b2b.private_key_pem_filename
                elif (
                    ".pfx"
                    in b2b_wsse_config_dict["wsse_profiles"][wsse_profile]["cert_file"]
                    or ".p12"
                    in b2b_wsse_config_dict["wsse_profiles"][wsse_profile]["cert_file"]
                ):
                    b2b.private_key_pfx_filename = b2b_wsse_config_dict[
                        "wsse_profiles"
                    ][wsse_profile]["cert_file"]
                else:
                    problem_detected = True
                    log.error(
                        "CAISO-106: No valid cert file found for "
                        + wsse_profile
                        + ". A .pfx, .p12, or .pem file is needed"
                    )
            else:
                problem_detected = True
                log.error(
                    "CAISO-115: No cert_file field found for profile "
                    + wsse_profile
                    + " in "
                    + b2b_config_dict["wsse_config_file"]
                )

        else:
            problem_detected = True
            log.error(
                "CAISO-105: No WSSE profile matching name: '" + wsse_profile + "'"
            )
            log.error(
                "CAISO-105: Or the profile has no fields "
                + "(username, cert_file, and cert_pass are needed)."
            )

    else:
        problem_detected = True
        log.error(
            "CAISO-104: Not signing this, wsse_profile field not found for service "
            + service
            + " in config"
        )

    return problem_detected


# ----------------------------------------------------------------------------------------------------
def retrieveChecks(b2b_config_dict, service, opts, b2b, problem_detected):

    # This is a retrieve service so we'll get the things necessary for one
    if opts.request_body:  # Command Line request body
        # If the command line points to a request body file
        if os.path.isfile(opts.request_body):
            with open(opts.request_body) as f:
                b2b.request_body = f.read()
        # Else treat it as XML
        else:
            b2b.request_body = opts.request_body
    else:  # Config file request body
        if (
            "request_body" in b2b_config_dict["services"][service]
            and b2b_config_dict["services"][service]["request_body"] is not None
        ):
            # If the request body field points to a file
            if os.path.isfile(b2b_config_dict["services"][service]["request_body"]):
                with open(b2b_config_dict["services"][service]["request_body"]) as f:
                    b2b.request_body = f.read()
            # Else treat it as XML
            else:
                b2b.request_body = b2b_config_dict["services"][service]["request_body"]
        else:
            problem_detected = True
            log.error(
                "CAISO-112: No request_body has been defined for retrieve service "
                + service
            )

    return problem_detected


# ----------------------------------------------------------------------------------------------------
def submitChecks(b2b_config_dict, service, opts, b2b, problem_detected):

    # This is a submit service so we'll get the things necessary for one
    if opts.attachment_file:  # Command line attachment file
        b2b.attachment_file = opts.attachment_file
    else:  # Config file attachment file
        if (
            "attachment_file" in b2b_config_dict["services"][service]
            and b2b_config_dict["services"][service]["attachment_file"] is not None
        ):
            b2b.attachment_file = b2b_config_dict["services"][service][
                "attachment_file"
            ]
        else:
            problem_detected = True
            log.error(
                "CAISO-113: No attachment_file has been defined for submit service "
                + service
            )

    # DocAttach submits put the attachment in the request body
    if "DocAttach" in service:
        b2b.request_body = "<fixme></fixme>"
    else:  # Otherwise they use a MIME multipart structure
        b2b.request_body = (
            '<ISOAttachment xmlns="http://www.caiso.com/soa/2006-10-26/ISOAttachment.xsd">'
            + "<AttachmentValue>DOCATTACH_SUBMIT_UUE</AttachmentValue>"
            + "</ISOAttachment>"
        )

    return problem_detected


# ----------------------------------------------------------------------------------------------------
def main():

    try:
        log.info("~~~~~~~~ START OF SESSION ~~~~~~~~")
        service_list = []
        problem_detected = False

        # Adding services to our execution list
        if "services" in b2b_config_dict and b2b_config_dict["services"] is not None:
            # If we are testing all services:
            if opts.test_all:
                for service in b2b_config_dict["services"]:
                    if b2b_config_dict["services"][service] is not None:
                        log.info("Adding " + service + " to service list")
                        service_list.append(service)
                    else:
                        log.error(
                            "CAISO-118: Service '"
                            + service
                            + "' has no fields defined underneath it"
                        )
            # If we are testing one service
            elif opts.service:
                if (
                    opts.service in b2b_config_dict["services"]
                    and b2b_config_dict["services"][opts.service] is not None
                ):
                    service_list.append(opts.service)
                    log.info("OK -- service exists in config")
                else:
                    problem_detected = True
                    log.error(
                        "CAISO-100: Service ("
                        + opts.service
                        + ") does not exist in config or is an empty section"
                    )
        else:
            problem_detected = True
            log.error(
                "CAISO-109: No services section found in "
                + opts.config_file
                + " or services section is empty"
            )

        # Checking for the various service-independent sections
        problem_detected = topLevelChecks(
            b2b_config_dict, b2b_wsse_config_dict, problem_detected
        )

        # Since these errors are ones that will cause
        # the program to crash later on, we'll leave here
        if problem_detected is True:
            log.error(
                "One or more top level problems occured when parsing "
                + opts.config_file
            )
            return

        for service in service_list:

            log.info(service + " Performing Checks ...")
            with tempfile.TemporaryDirectory() as tmpdirname:

                b2b = caisopy_b2b.CAISOB2BUtils(log=log)
                b2b.verbose = opts.verbose
                b2b.service = service
                b2b.tmpdirname = tmpdirname
                b2b.openssl_path = b2b_config_dict["openssl_path"]
                problem_detected = False

                # Grabbing endpoint and checking for errors
                problem_detected = endpointChecks(
                    b2b_config_dict, opts.environment, service, b2b, problem_detected
                )

                # Getting service components
                if "retrieve" in service:
                    b2b.unpack_retrieve_attachments = opts.unpack_retrieve_attachments
                    problem_detected = retrieveChecks(
                        b2b_config_dict, service, opts, b2b, problem_detected
                    )
                elif "submit" in service:
                    problem_detected = submitChecks(
                        b2b_config_dict, service, opts, b2b, problem_detected
                    )
                else:
                    problem_detected = True
                    log.error(
                        "CAISO-107: Service is not recognized as a retrieve or a submit"
                    )

                # Check for soapaction in service
                if "soapaction" in b2b_config_dict["services"][service]:
                    b2b.soapaction = b2b_config_dict["services"][service]["soapaction"]
                else:
                    problem_detected = True
                    log.error(
                        "CAISO-114: No soapaction field has been defined for service "
                        + service
                    )

                # Getting the certificate information and checking for errors
                problem_detected = wsseChecks(
                    b2b_config_dict,
                    b2b_wsse_config_dict,
                    service,
                    b2b,
                    problem_detected,
                )

                if problem_detected is False:
                    log.info("All checks passed! Submitting request ...")
                    response_dict = b2b.submit()
                    if response_dict is not None and opts.responsedump:
                        # Response dict will have the response xml + any attachments
                        log.info(
                            "Here are the contents of the response dictionary at the end"
                        )
                        log.info(pp.pformat(response_dict))
                else:
                    log.error(
                        "One or more errors happened while attempting to execute "
                        + service
                        + " that stop it from being submitted"
                    )

            log.info(service + " Finished")

    except Exception as err:
        raise Exception("CAISO-602: Problem in b2b main") from err


# ----------------------------------------------------------------------------------------------------
if __name__ == "__main__":

    # Set b2b_config_dict
    b2b_config_dict = {}

    # Handler for pretty printing (like Data Dumper)
    pp = pprint.PrettyPrinter(indent=4)

    try:

        # Parse command line args
        opts = argParser()

        try:

            # Read in main configuration file
            b2b_config_dict = {}
            if os.path.isfile(opts.config_file):
                with open(opts.config_file) as f:
                    try:
                        b2b_config_dict = yaml.safe_load(f)
                    except yaml.YAMLError as exc:
                        print(
                            "CAISO-197: YAML error occured while parsing "
                            + opts.config_file
                            + ": "
                        )
                        print(exc)
                        print("Please make sure your configuration file is proper YAML")
                        sys.exit(1)
            else:
                print(
                    "CAISO-199: No config file: "
                    + opts.config_file
                    + " Does the config file exist?"
                )
                sys.exit(1)
            if b2b_config_dict is None:
                print(
                    "CAISO-111: Nothing was retrieved while parsing config file "
                    + opts.config_file
                )
                print("Is it empty? Does it have YAML formatting?")
                sys.exit(1)

            # Read in the WSSE config file
            b2b_wsse_config_dict = {}
            if (
                "wsse_config_file" in b2b_config_dict
                and b2b_config_dict["wsse_config_file"] is not None
            ):
                if os.path.isfile(b2b_config_dict["wsse_config_file"]):
                    with open(b2b_config_dict["wsse_config_file"]) as f:
                        try:
                            b2b_wsse_config_dict = yaml.safe_load(f)
                        except yaml.YAMLError as exc:
                            print(
                                "CAISO-196: YAML error occured while parsing "
                                + b2b_config_dict["wsse_config_file"]
                                + ": "
                            )
                            print(exc)
                            print(
                                "Please make sure your configuration file is proper YAML"
                            )
                            sys.exit(1)
                else:
                    print(
                        "CAISO-198: No WSSE config file: "
                        + b2b_config_dict["wsse_config_file"]
                        + " does the WSSE config file exist?"
                    )
                    sys.exit(1)
            else:
                print(
                    "CAISO-108: No wsse_config_file field defined in "
                    + opts.config_file
                )
                sys.exit(1)

            # Setting up logging now that we know where the logs should go
            log = initLogging()

            if opts.verbose:
                log.setLevel(logging.DEBUG)

        except Exception as err:
            raise Exception(
                "CAISO-603: Check the "
                + str(opts.config_file)
                + " file for proper YAML formatting"
            ) from err

        # Call main
        main()

    except Exception as err:
        raise Exception(
            "CAISO-604: MAIN, err="
            + str(err)
            + " lineno="
            + sys.exc_info()[2].tb_lineno
        )

    finally:

        print("b2b finished")

        sys.exit(0)
