@{
    # PSScriptAnalyzer baseline for a production PowerShell module repo.
    # Goal: catch risky patterns early, keep style consistent, and keep CI noise manageable.

    # Always include Microsoft/community default rules.
    IncludeDefaultRules = $true

    # Analyze script + module files; CI can call Invoke-ScriptAnalyzer with -Recurse.
    Recurse = $true

    # Treat severities as the primary gate. (Common CI approach: fail on Error.)
    Severity = @('Error', 'Warning')

    # Optional: if you create custom rules later, point to them here.
    # CustomRulePath = @('.\tools\PSScriptAnalyzerRules.psm1')

    # Suppressions / exclusions:
    # Keep this list short. Prefer local SuppressMessage attributes for one-off cases.
    ExcludeRules = @(
        # Loader pattern often dot-sources files; keep enabled if you prefer stricter rules.
        # 'PSAvoidUsingDotSourcing'
    )

    Rules = @{
        # -------------------------
        # SECURITY / HIGH-VALUE RULES
        # -------------------------

        # Avoid Invoke-Expression (high-risk). Keep enabled.
        PSAvoidUsingInvokeExpression = @{
            Enable = $true
        }

        # Avoid ConvertTo-SecureString -AsPlainText patterns in repo code.
        # (This rule is not always present in all analyzer versions; if absent, no harm.)
        PSAvoidUsingConvertToSecureStringWithPlainText = @{
            Enable = $true
        }

        # Avoid plain text passwords. (If your analyzer version includes it.)
        PSAvoidUsingPlainTextForPassword = @{
            Enable = $true
        }

        # -------------------------
        # STYLE / MAINTAINABILITY
        # -------------------------

        # Enforce approved verbs (important for modules).
        PSUseApprovedVerbs = @{
            Enable = $true
        }

        # Enforce consistent casing in keywords (readability).
        PSUseConsistentWhitespace = @{
            Enable = $true

            # Standard spacing options
            CheckOpenBrace        = $true
            CheckCloseBrace       = $true
            CheckOpenParen        = $true
            CheckCloseParen       = $true
            CheckOperator         = $true
            CheckSeparator        = $true
            CheckParameter        = $true
            IgnoreAssignmentOperatorInsideHashTable = $true
        }

        # Catch common uninitialized variable mistakes.
        PSUseDeclaredVarsMoreThanAssignments = @{
            Enable = $true
        }

        # Encourage explicit parameter binding patterns / clearer function boundaries.
        PSAvoidDefaultValueForMandatoryParameter = @{
            Enable = $true
        }

        # Prefer explicit, intentional comparisons.
        PSUseComparisonOperatorCorrectly = @{
            Enable = $true
        }

        # Discourage Write-Host in non-UI code (hard to test/capture).
        PSAvoidUsingWriteHost = @{
            Enable = $true
        }

        # -------------------------
        # MODULE/REPO PRACTICALITIES
        # -------------------------

        # Your repo may intentionally use non-standard casing in filenames/functions for legacy reasons.
        # Keep enabled by default; suppress locally if needed.
        PSUseSingularNouns = @{
            Enable = $true
        }

        # Avoid aliases for readability in shared code.
        PSAvoidUsingCmdletAliases = @{
            Enable = $true
            # Allow common aliases in very small scripts if you want:
            # Whitelist = @('Where','ForEach')
        }

        # Align with secure coding: avoid hard-coded paths when possible.
        PSAvoidUsingHardCodedPath = @{
            Enable = $true
        }

        # Script/module encoding: keep consistent. (If supported by your analyzer version.)
        # Some environments enforce UTF8 w/ BOM or w/out BOM; decide in .editorconfig.
        # PSUseBOMForUnicodeEncodedFile = @{ Enable = $false }

        # If you use global scope intentionally in loader scripts, suppress locally rather than disabling.
        PSAvoidGlobalVars = @{
            Enable = $true
        }
    }
}