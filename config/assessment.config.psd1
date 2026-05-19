@{
    Edition        = 'Lite'
    OutputPath     = '.\Output'
    EnabledChecks  = @('CA-001','PIM-001','LA-001')
    AuthMethod     = 'Certificate'
    ReportOptions  = @{
        IncludeEvidence = $true
        HtmlTheme       = 'default'
    }
}
