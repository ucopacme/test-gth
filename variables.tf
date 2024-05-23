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
    error_message = "a var.uri_pattern_exceptions rule group key is not valid. Rule group keys must be in: AWSManagedRulesCommonRuleSet, AWSManagedRulesAdminProtectionRuleSet, AWSManagedRulesKnownBadInputsRuleSet, AWSManagedRulesSQLiRuleSet, AWSManagedRulesLinuxRuleSet, AWSManagedRulesUnixRuleSet, AWSManagedRulesWindowsRuleSet, AWSManagedRulesPHPRuleSet, AWSManagedRulesWordPressRuleSet."
  }
}
