/**
 * Error type: missing import (RemoteFlowSource used without import)
 * Error type: wrong class name in extends (DataFlow::Config vs DataFlow::Configuration)
 */
import java
import semmle.code.java.dataflow.DataFlow
// MISSING: import semmle.code.java.dataflow.FlowSources

class MyConfig extends DataFlow::Configuration {
  //                ^^^^^^^^^^^^^^^^^^^^^^
  //                ERROR: DataFlow::Configuration is not a valid type

  MyConfig() { this = "MyConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
    //               ^^^^^^^^^^^^^^^^
    // ERROR: could not resolve type RemoteFlowSource (missing import)
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().hasName("executeQuery") and
      sink.asExpr() = ma
    )
  }
}

from MyConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, source, sink, "$@ flows to $@", source, "source", sink, "sink"
