/**
 * Error type: incomplete ConfigSig (missing isBarrier)
 * Error type: @kind mismatch with select clause
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

module MyIncompleteConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().hasName("executeQuery") and
      sink.asExpr() = ma
    )
  }

  // MISSING: predicate isBarrier(DataFlow::Node node)
  // Not all ConfigSig predicates are implemented
}

import MyIncompleteConfig::Flow

from MyIncompleteConfig::Flow::PathNode source, MyIncompleteConfig::Flow::PathNode sink
where MyIncompleteConfig::Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "$@", source, "source"
