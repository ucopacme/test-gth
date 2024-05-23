variable "uri_pattern_exceptions" {
  description = "Map of regexes to be labeled as exceptions, keyed from rule group, rule name"
  type        = map(map(list(string)))

  default = {
    "AWSManagedRulesCommonRuleSet" = {
      "NoUserAgent_HEADER"                  = []
      "UserAgent_BadBots_HEADER"            = []
      "SizeRestrictions_QUERYSTRING"        = []
      "SizeRestrictions_Cookie_HEADER"      = []
      "SizeRestrictions_BODY"               = []
      "SizeRestrictions_URIPATH"            = []
      "EC2MetaDataSSRF_BODY"                = []
      "EC2MetaDataSSRF_COOKIE"              = []
      "EC2MetaDataSSRF_URIPATH"             = []
      "EC2MetaDataSSRF_QUERYARGUMENTS"      = []
      "GenericLFI_QUERYARGUMENTS"           = []
      "GenericLFI_URIPATH"                  = []
      "GenericLFI_BODY"                     = []
      "RestrictedExtensions_URIPATH"        = []
      "RestrictedExtensions_QUERYARGUMENTS" = []
      "GenericRFI_QUERYARGUMENTS"           = []
      "GenericRFI_BODY"                     = []
      "GenericRFI_URIPATH"                  = []
      "CrossSiteScripting_COOKIE"           = []
      "CrossSiteScripting_QUERYARGUMENTS"   = []
      "CrossSiteScripting_BODY"             = []
      "CrossSiteScripting_URIPATH"          = []
    }
    "AWSManagedRulesAdminProtectionRuleSet" = {
      "AdminProtection_URIPATH" = []
    }
    "AWSManagedRulesKnownBadInputsRuleSet" = {
      "JavaDeserializationRCE_HEADER"      = []
      "JavaDeserializationRCE_BODY"        = []
      "JavaDeserializationRCE_URIPATH"     = []
      "JavaDeserializationRCE_QUERYSTRING" = []
      "Host_localhost_HEADER"              = []
      "PROPFIND_METHOD"                    = []
      "ExploitablePaths_URIPATH"           = []
      "Log4JRCE_HEADER"                    = []
      "Log4JRCE_QUERYSTRING"               = []
      "Log4JRCE_BODY"                      = []
      "Log4JRCE_URIPATH"                   = []
    }
    "AWSManagedRulesSQLiRuleSet" = {
      "SQLi_QUERYARGUMENTS"                 = []
      "SQLiExtendedPatterns_QUERYARGUMENTS" = []
      "SQLi_BODY"                           = []
      "SQLiExtendedPatterns_BODY"           = []
      "SQLi_COOKIE"                         = []
    }
    "AWSManagedRulesLinuxRuleSet" = {
      "LFI_URIPATH"     = []
      "LFI_QUERYSTRING" = []
      "LFI_HEADER"      = []
    }
    "AWSManagedRulesUnixRuleSet" = {
      "UNIXShellCommandsVariables_QUERYARGUMENTS" = []
      "UNIXShellCommandsVariables_BODY"           = []
    }
    "AWSManagedRulesWindowsRuleSet" = {
      "WindowsShellCommands_COOKIE"         = []
      "WindowsShellCommands_QUERYARGUMENTS" = []
      "WindowsShellCommands_BODY"           = []
      "PowerShellCommands_COOKIE"           = []
      "PowerShellCommands_QUERYARGUMENTS"   = []
      "PowerShellCommands_BODY"             = []
    }
    "AWSManagedRulesPHPRuleSet" = {
      "PHPHighRiskMethodsVariables_HEADER"      = []
      "PHPHighRiskMethodsVariables_QUERYSTRING" = []
      "PHPHighRiskMethodsVariables_BODY"        = []
    }
    "AWSManagedRulesWordPressRuleSet" = {
      "WordPressExploitableCommands_QUERYSTRING" = []
      "WordPressExploitablePaths_URIPATH"        = []
    }
  }

  validation {
    condition     = length(setintersection(keys(var.uri_pattern_exceptions), ["AWSManagedRulesCommonRuleSet", "AWSManagedRulesAdminProtectionRuleSet", "AWSManagedRulesKnownBadInputsRuleSet", "AWSManagedRulesSQLiRuleSet", "AWSManagedRulesLinuxRuleSet", "AWSManagedRulesUnixRuleSet", "AWSManagedRulesWindowsRuleSet", "AWSManagedRulesPHPRuleSet", "AWSManagedRulesWordPressRuleSet"])) == length(keys(var.uri_pattern_exceptions))
    error_message = "A var.uri_pattern_exceptions rule group key is not valid. Rule group keys must be in: AWSManagedRulesCommonRuleSet, AWSManagedRulesAdminProtectionRuleSet, AWSManagedRulesKnownBadInputsRuleSet, AWSManagedRulesSQLiRuleSet, AWSManagedRulesLinuxRuleSet, AWSManagedRulesUnixRuleSet, AWSManagedRulesWindowsRuleSet, AWSManagedRulesPHPRuleSet, AWSManagedRulesWordPressRuleSet."
  }

  validation {
    condition     = contains(keys(var.uri_pattern_exceptions), "AWSManagedRulesCommonRuleSet") ? length(setintersection(keys(var.uri_pattern_exceptions["AWSManagedRulesCommonRuleSet"]), ["NoUserAgent_HEADER", "UserAgent_BadBots_HEADER", "SizeRestrictions_QUERYSTRING", "SizeRestrictions_Cookie_HEADER", "SizeRestrictions_BODY", "SizeRestrictions_URIPATH", "EC2MetaDataSSRF_BODY", "EC2MetaDataSSRF_COOKIE", "EC2MetaDataSSRF_URIPATH", "EC2MetaDataSSRF_QUERYARGUMENTS", "GenericLFI_QUERYARGUMENTS", "GenericLFI_URIPATH", "GenericLFI_BODY", "RestrictedExtensions_URIPATH", "RestrictedExtensions_QUERYARGUMENTS", "GenericRFI_QUERYARGUMENTS", "GenericRFI_BODY", "GenericRFI_URIPATH", "CrossSiteScripting_COOKIE", "CrossSiteScripting_QUERYARGUMENTS", "CrossSiteScripting_BODY", "CrossSiteScripting_URIPATH"])) == length(keys(var.uri_pattern_exceptions["AWSManagedRulesCommonRuleSet"])) : true
    error_message = "A var.uri_pattern_exceptions AWSManagedRulesCommonRuleSet rule name key is not valid. AWSManagedRulesCommonRuleSet rule name keys must be in: NoUserAgent_HEADER, UserAgent_BadBots_HEADER, SizeRestrictions_QUERYSTRING, SizeRestrictions_Cookie_HEADER, SizeRestrictions_BODY, SizeRestrictions_URIPATH, EC2MetaDataSSRF_BODY, EC2MetaDataSSRF_COOKIE, EC2MetaDataSSRF_URIPATH, EC2MetaDataSSRF_QUERYARGUMENTS, GenericLFI_QUERYARGUMENTS, GenericLFI_URIPATH, GenericLFI_BODY, RestrictedExtensions_URIPATH, RestrictedExtensions_QUERYARGUMENTS, GenericRFI_QUERYARGUMENTS, GenericRFI_BODY, GenericRFI_URIPATH, CrossSiteScripting_COOKIE, CrossSiteScripting_QUERYARGUMENTS, CrossSiteScripting_BODY, CrossSiteScripting_URIPATH."
  }

  validation {
    condition     = contains(keys(var.uri_pattern_exceptions), "AWSManagedRulesAdminProtectionRuleSet") ? length(setintersection(keys(var.uri_pattern_exceptions["AWSManagedRulesAdminProtectionRuleSet"]), ["AdminProtection_URIPATH"])) == length(keys(var.uri_pattern_exceptions["AWSManagedRulesAdminProtectionRuleSet"])) : true
    error_message = "A var.uri_pattern_exceptions AWSManagedRulesAdminProtectionRuleSet rule name key is not valid. AWSManagedRulesAdminProtectionRuleSet rule name keys must be in: AdminProtection_URIPATH."
  }

  validation {
    condition     = contains(keys(var.uri_pattern_exceptions), "AWSManagedRulesKnownBadInputsRuleSet") ? length(setintersection(keys(var.uri_pattern_exceptions["AWSManagedRulesKnownBadInputsRuleSet"]), ["JavaDeserializationRCE_HEADER", "JavaDeserializationRCE_BODY", "JavaDeserializationRCE_URIPATH", "JavaDeserializationRCE_QUERYSTRING", "Host_localhost_HEADER", "PROPFIND_METHOD", "ExploitablePaths_URIPATH", "Log4JRCE_HEADER", "Log4JRCE_QUERYSTRING", "Log4JRCE_BODY", "Log4JRCE_URIPATH"])) == length(keys(var.uri_pattern_exceptions["AWSManagedRulesKnownBadInputsRuleSet"])) : true
    error_message = "A var.uri_pattern_exceptions AWSManagedRulesKnownBadInputsRuleSet rule name key is not valid. AWSManagedRulesKnownBadInputsRuleSet rule name keys must be in: JavaDeserializationRCE_HEADER, JavaDeserializationRCE_BODY, JavaDeserializationRCE_URIPATH, JavaDeserializationRCE_QUERYSTRING, Host_localhost_HEADER, PROPFIND_METHOD, ExploitablePaths_URIPATH, Log4JRCE_HEADER, Log4JRCE_QUERYSTRING, Log4JRCE_BODY, Log4JRCE_URIPATH."
  }

  validation {
    condition     = contains(keys(var.uri_pattern_exceptions), "AWSManagedRulesSQLiRuleSet") ? length(setintersection(keys(var.uri_pattern_exceptions["AWSManagedRulesSQLiRuleSet"]), ["SQLi_QUERYARGUMENTS", "SQLiExtendedPatterns_QUERYARGUMENTS", "SQLi_BODY", "SQLiExtendedPatterns_BODY", "SQLi_COOKIE"])) == length(keys(var.uri_pattern_exceptions["AWSManagedRulesSQLiRuleSet"])) : true
    error_message = "A var.uri_pattern_exceptions AWSManagedRulesSQLiRuleSet rule name key is not valid. AWSManagedRulesSQLiRuleSet rule name keys must be in: SQLi_QUERYARGUMENTS, SQLiExtendedPatterns_QUERYARGUMENTS, SQLi_BODY, SQLiExtendedPatterns_BODY, SQLi_COOKIE."
  }

  validation {
    condition     = contains(keys(var.uri_pattern_exceptions), "AWSManagedRulesLinuxRuleSet") ? length(setintersection(keys(var.uri_pattern_exceptions["AWSManagedRulesLinuxRuleSet"]), ["LFI_URIPATH", "LFI_QUERYSTRING", "LFI_HEADER"])) == length(keys(var.uri_pattern_exceptions["AWSManagedRulesLinuxRuleSet"])) : true
    error_message = "A var.uri_pattern_exceptions AWSManagedRulesLinuxRuleSet rule name key is not valid. AWSManagedRulesLinuxRuleSet rule name keys must be in: LFI_URIPATH, LFI_QUERYSTRING, LFI_HEADER."
  }

  validation {
    condition     = contains(keys(var.uri_pattern_exceptions), "AWSManagedRulesUnixRuleSet") ? length(setintersection(keys(var.uri_pattern_exceptions["AWSManagedRulesUnixRuleSet"]), ["UNIXShellCommandsVariables_QUERYARGUMENTS", "UNIXShellCommandsVariables_BODY"])) == length(keys(var.uri_pattern_exceptions["AWSManagedRulesUnixRuleSet"])) : true
    error_message = "A var.uri_pattern_exceptions AWSManagedRulesUnixRuleSet rule name key is not valid. AWSManagedRulesUnixRuleSet rule name keys must be in: UNIXShellCommandsVariables_QUERYARGUMENTS, UNIXShellCommandsVariables_BODY."
  }

  validation {
    condition     = contains(keys(var.uri_pattern_exceptions), "AWSManagedRulesWindowsRuleSet") ? length(setintersection(keys(var.uri_pattern_exceptions["AWSManagedRulesWindowsRuleSet"]), ["WindowsShellCommands_COOKIE", "WindowsShellCommands_QUERYARGUMENTS", "WindowsShellCommands_BODY", "PowerShellCommands_COOKIE", "PowerShellCommands_QUERYARGUMENTS", "PowerShellCommands_BODY"])) == length(keys(var.uri_pattern_exceptions["AWSManagedRulesWindowsRuleSet"])) : true
    error_message = "A var.uri_pattern_exceptions AWSManagedRulesWindowsRuleSet rule name key is not valid. AWSManagedRulesWindowsRuleSet rule name keys must be in: WindowsShellCommands_COOKIE, WindowsShellCommands_QUERYARGUMENTS, WindowsShellCommands_BODY, PowerShellCommands_COOKIE, PowerShellCommands_QUERYARGUMENTS, PowerShellCommands_BODY."
  }

  validation {
    condition     = contains(keys(var.uri_pattern_exceptions), "AWSManagedRulesPHPRuleSet") ? length(setintersection(keys(var.uri_pattern_exceptions["AWSManagedRulesPHPRuleSet"]), ["PHPHighRiskMethodsVariables_HEADER", "PHPHighRiskMethodsVariables_QUERYSTRING", "PHPHighRiskMethodsVariables_BODY"])) == length(keys(var.uri_pattern_exceptions["AWSManagedRulesPHPRuleSet"])) : true
    error_message = "A var.uri_pattern_exceptions AWSManagedRulesPHPRuleSet rule name key is not valid. AWSManagedRulesPHPRuleSet rule name keys must be in: PHPHighRiskMethodsVariables_HEADER, PHPHighRiskMethodsVariables_QUERYSTRING, PHPHighRiskMethodsVariables_BODY."
  }

  validation {
    condition     = contains(keys(var.uri_pattern_exceptions), "AWSManagedRulesWordPressRuleSet") ? length(setintersection(keys(var.uri_pattern_exceptions["AWSManagedRulesWordPressRuleSet"]), ["WordPressExploitableCommands_QUERYSTRING", "WordPressExploitablePaths_URIPATH"])) == length(keys(var.uri_pattern_exceptions["AWSManagedRulesWordPressRuleSet"])) : true
    error_message = "A var.uri_pattern_exceptions AWSManagedRulesWordPressRuleSet rule name key is not valid. AWSManagedRulesWordPressRuleSet rule name keys must be in: WordPressExploitableCommands_QUERYSTRING, WordPressExploitablePaths_URIPATH."
  }
}
