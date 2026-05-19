BeforeAll { . "$PSScriptRoot/../../src/Private/policy/Test-WriteAllowed.ps1" }

Describe 'Test-WriteAllowed' {
    It 'returns true when all 4 gates pass' {
        Test-WriteAllowed -Mode 'Remediate' -AuthMethod 'Delegated' -WhatIf $false -Edition 'Premium' | Should -BeTrue
    }
    It 'returns false when Mode != Remediate' {
        Test-WriteAllowed -Mode 'Assess' -AuthMethod 'Delegated' -WhatIf $false -Edition 'Premium' | Should -BeFalse
    }
    It 'returns false when AuthMethod != Delegated' {
        Test-WriteAllowed -Mode 'Remediate' -AuthMethod 'Certificate' -WhatIf $false -Edition 'Premium' | Should -BeFalse
    }
    It 'returns false when WhatIf = true' {
        Test-WriteAllowed -Mode 'Remediate' -AuthMethod 'Delegated' -WhatIf $true -Edition 'Premium' | Should -BeFalse
    }
    It 'returns false when Edition != Premium' {
        Test-WriteAllowed -Mode 'Remediate' -AuthMethod 'Delegated' -WhatIf $false -Edition 'Lite' | Should -BeFalse
    }
    It 'returns false when 2 gates fail' {
        Test-WriteAllowed -Mode 'Assess' -AuthMethod 'Delegated' -WhatIf $false -Edition 'Lite' | Should -BeFalse
    }
}
