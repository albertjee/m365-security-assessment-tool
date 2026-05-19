BeforeAll {
    . "$PSScriptRoot/../src/Public/Invoke-M365Assessment.ps1"

    function Start-AssessmentPipeline { param($Params) throw 'Start-AssessmentPipeline stub — must be mocked per test' }
}

Describe 'Invoke-M365Assessment — parameter validation' {
    It 'accepts valid Mode=Assess' {
        Mock Start-AssessmentPipeline {}
        { Invoke-M365Assessment -Mode Assess -AuthMethod Certificate -TenantId 'tenant-001' -AppId 'app-001' } |
            Should -Not -Throw
    }

    It 'accepts valid Mode=Remediate with Delegated' {
        Mock Start-AssessmentPipeline {}
        { Invoke-M365Assessment -Mode Remediate -AuthMethod Delegated -TenantId 'tenant-001' -AppId 'app-001' -Confirm:$false } |
            Should -Not -Throw
    }

    It 'rejects invalid Mode value' {
        { Invoke-M365Assessment -Mode InvalidMode -AuthMethod Certificate -TenantId 'tid' -AppId 'aid' } |
            Should -Throw
    }

    It 'rejects invalid AuthMethod value' {
        { Invoke-M365Assessment -Mode Assess -AuthMethod BadAuth -TenantId 'tid' -AppId 'aid' } |
            Should -Throw
    }

    It 'requires TenantId' {
        { Invoke-M365Assessment -Mode Assess -AuthMethod Certificate -AppId 'aid' } |
            Should -Throw
    }

    It 'requires AppId' {
        { Invoke-M365Assessment -Mode Assess -AuthMethod Certificate -TenantId 'tid' } |
            Should -Throw
    }
}

Describe 'Invoke-M365Assessment — delegates to pipeline' {
    It 'calls Start-AssessmentPipeline once with parameters' {
        Mock Start-AssessmentPipeline {}

        Invoke-M365Assessment -Mode Assess -AuthMethod Certificate -TenantId 'tid' -AppId 'aid'

        Should -Invoke Start-AssessmentPipeline -Times 1
    }

    It 'passes IncludeChecks through to pipeline' {
        $script:capturedParams = $null
        Mock Start-AssessmentPipeline { $script:capturedParams = $Params }

        Invoke-M365Assessment -Mode Assess -AuthMethod Certificate -TenantId 'tid' -AppId 'aid' -IncludeChecks @('CA-001','PIM-001')

        $script:capturedParams.IncludeChecks | Should -Contain 'CA-001'
        $script:capturedParams.IncludeChecks | Should -Contain 'PIM-001'
    }

    It 'passes Edition through to pipeline when specified' {
        $script:capturedParams = $null
        Mock Start-AssessmentPipeline { $script:capturedParams = $Params }

        Invoke-M365Assessment -Mode Assess -AuthMethod Certificate -TenantId 'tid' -AppId 'aid' -Edition Premium

        $script:capturedParams.Edition | Should -Be 'Premium'
    }
}

Describe 'Invoke-M365Assessment — ShouldProcess' {
    It 'supports -WhatIf parameter without error' {
        Mock Start-AssessmentPipeline {}
        { Invoke-M365Assessment -Mode Assess -AuthMethod Certificate -TenantId 'tid' -AppId 'aid' -WhatIf } |
            Should -Not -Throw
    }
}
