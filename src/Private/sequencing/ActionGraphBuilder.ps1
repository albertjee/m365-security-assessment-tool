Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Build-ActionGraph {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Actions)

    $nodes = [System.Collections.Generic.Dictionary[string,object]]::new()
    $edges = [System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[string]]]::new()

    foreach ($action in $Actions) {
        $id = $action.action.actionId
        $nodes[$id] = $action
        if (-not $edges.ContainsKey($id)) {
            $edges[$id] = [System.Collections.Generic.List[string]]::new()
        }
        foreach ($dep in @($action.sequence.dependencies)) {
            if ($dep) { $edges[$id].Add($dep) }
        }
    }

    return [PSCustomObject]@{ Nodes = $nodes; Edges = $edges }
}

function Test-AcyclicGraph {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Graph)

    $inDegree = [System.Collections.Generic.Dictionary[string,int]]::new()
    foreach ($id in $Graph.Nodes.Keys) { $inDegree[$id] = 0 }

    foreach ($id in $Graph.Edges.Keys) {
        foreach ($dep in $Graph.Edges[$id]) {
            if ($Graph.Nodes.ContainsKey($dep)) {
                $inDegree[$id] = $inDegree[$id] + 1
            }
        }
    }

    $queue = [System.Collections.Generic.Queue[string]]::new()
    foreach ($id in ($inDegree.Keys | Sort-Object)) {
        if ($inDegree[$id] -eq 0) { $queue.Enqueue($id) }
    }

    $processed = 0
    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        $processed++
        foreach ($id in $Graph.Edges.Keys) {
            if ($Graph.Edges[$id] -contains $current) {
                $inDegree[$id] = $inDegree[$id] - 1
                if ($inDegree[$id] -eq 0) { $queue.Enqueue($id) }
            }
        }
    }

    if ($processed -ne $Graph.Nodes.Count) {
        $cycleNodes = $Graph.Nodes.Keys | Where-Object { $inDegree[$_] -gt 0 }
        throw [System.InvalidOperationException]::new(
            "CircularDependency detected in action graph. Nodes involved: $($cycleNodes -join ', ')"
        )
    }
}

function Get-TopologicalOrder {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Graph)

    Test-AcyclicGraph -Graph $Graph

    $inDegree = [System.Collections.Generic.Dictionary[string,int]]::new()
    foreach ($id in $Graph.Nodes.Keys) { $inDegree[$id] = 0 }
    foreach ($id in $Graph.Edges.Keys) {
        foreach ($dep in $Graph.Edges[$id]) {
            if ($Graph.Nodes.ContainsKey($dep)) { $inDegree[$id]++ }
        }
    }

    $queue  = [System.Collections.Generic.SortedSet[string]]::new()
    $result = [System.Collections.Generic.List[string]]::new()

    foreach ($id in $inDegree.Keys) {
        if ($inDegree[$id] -eq 0) { $queue.Add($id) | Out-Null }
    }

    while ($queue.Count -gt 0) {
        $current = $queue.Min
        $queue.Remove($current) | Out-Null
        $result.Add($current)
        foreach ($id in ($Graph.Edges.Keys | Sort-Object)) {
            if ($Graph.Edges[$id] -contains $current) {
                $inDegree[$id]--
                if ($inDegree[$id] -eq 0) { $queue.Add($id) | Out-Null }
            }
        }
    }

    return $result.ToArray()
}
