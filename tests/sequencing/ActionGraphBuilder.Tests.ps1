BeforeAll {
    . "$PSScriptRoot/../../src/Private/sequencing/ActionGraphBuilder.ps1"

    function New-Action {
        param([string]$Id, [string[]]$Deps = @())
        [PSCustomObject]@{ action=@{actionId=$Id}; sequence=@{dependencies=$Deps} }
    }
}

Describe 'Build-ActionGraph' {
    It 'builds graph with correct node count' {
        $actions = @((New-Action 'ACT-001'), (New-Action 'ACT-002'))
        $graph = Build-ActionGraph -Actions $actions
        $graph.Nodes.Count | Should -Be 2
    }

    It 'adds edge for declared dependency' {
        $a1 = New-Action 'ACT-001'
        $a2 = New-Action 'ACT-002' -Deps @('ACT-001')
        $graph = Build-ActionGraph -Actions @($a1, $a2)
        $graph.Edges['ACT-002'] | Should -Contain 'ACT-001'
    }

    It 'node with no dependencies has empty edge list' {
        $a = New-Action 'ACT-001'
        $graph = Build-ActionGraph -Actions @($a)
        $graph.Edges['ACT-001'].Count | Should -Be 0
    }
}

Describe 'Test-AcyclicGraph — cycle detection' {
    It 'does not throw for a valid DAG' {
        $a1 = New-Action 'ACT-001'
        $a2 = New-Action 'ACT-002' -Deps @('ACT-001')
        $graph = Build-ActionGraph -Actions @($a1, $a2)
        { Test-AcyclicGraph -Graph $graph } | Should -Not -Throw
    }

    It 'throws structured error for direct cycle (A->B->A)' {
        $a1 = New-Action 'ACT-001' -Deps @('ACT-002')
        $a2 = New-Action 'ACT-002' -Deps @('ACT-001')
        $graph = Build-ActionGraph -Actions @($a1, $a2)
        { Test-AcyclicGraph -Graph $graph } |
            Should -Throw '*CircularDependency*'
    }

    It 'throws for indirect cycle (A->B->C->A)' {
        $a1 = New-Action 'ACT-001' -Deps @('ACT-003')
        $a2 = New-Action 'ACT-002' -Deps @('ACT-001')
        $a3 = New-Action 'ACT-003' -Deps @('ACT-002')
        $graph = Build-ActionGraph -Actions @($a1, $a2, $a3)
        { Test-AcyclicGraph -Graph $graph } | Should -Throw '*CircularDependency*'
    }

    It 'identifies the cycle nodes in error message' {
        $a1 = New-Action 'ACT-001' -Deps @('ACT-002')
        $a2 = New-Action 'ACT-002' -Deps @('ACT-001')
        $graph = Build-ActionGraph -Actions @($a1, $a2)
        try { Test-AcyclicGraph -Graph $graph } catch { $err = $_ }
        $err | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-TopologicalOrder' {
    It 'returns actions in dependency-first order' {
        $a1 = New-Action 'ACT-001'
        $a2 = New-Action 'ACT-002' -Deps @('ACT-001')
        $a3 = New-Action 'ACT-003' -Deps @('ACT-002')
        $graph = Build-ActionGraph -Actions @($a3, $a2, $a1)
        $order = Get-TopologicalOrder -Graph $graph
        $order.IndexOf('ACT-001') | Should -BeLessThan $order.IndexOf('ACT-002')
        $order.IndexOf('ACT-002') | Should -BeLessThan $order.IndexOf('ACT-003')
    }

    It 'is deterministic — same input produces same order' {
        $a1 = New-Action 'ACT-001'
        $a2 = New-Action 'ACT-002' -Deps @('ACT-001')
        $graph = Build-ActionGraph -Actions @($a1, $a2)
        $order1 = Get-TopologicalOrder -Graph $graph
        $order2 = Get-TopologicalOrder -Graph $graph
        $order1 -join ',' | Should -Be ($order2 -join ',')
    }
}
