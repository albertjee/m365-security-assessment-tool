@{
    RootModule           = 'm365-security-assessment-tool.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author               = 'Metis Security Ltd'
    CompanyName          = 'Metis Security Ltd'
    Description          = 'M365 tenant security assessment and remediation tool'
    PowerShellVersion    = '7.2'
    FunctionsToExport    = @('Invoke-M365Assessment')
    RequiredModules      = @(
        @{ ModuleName = 'Microsoft.Graph.Authentication';              ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Microsoft.Graph.Identity.SignIns';            ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Microsoft.Graph.Identity.Governance';         ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Microsoft.Graph.Identity.DirectoryManagement'; ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Microsoft.Graph.DeviceManagement';            ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Microsoft.Graph.Security';                    ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Microsoft.Graph.Reports';                     ModuleVersion = '2.0.0' }
        @{ ModuleName = 'ExchangeOnlineManagement';                    ModuleVersion = '3.0.0' }
    )
    PrivateData          = @{ PSData = @{ Tags = @('M365','Security','Assessment','Remediation') } }
}
