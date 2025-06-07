/**
 * @kind path-problem
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking

class NetworkByteSwap extends Expr {
    NetworkByteSwap () {
        exists(MacroInvocation mi |
            mi.getMacroName().matches("ntoh%")
            and mi.getExpr() = this
        )
    }
}

module MyConfig implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof NetworkByteSwap    
  }

  predicate isSink(DataFlow::Node sink) {
    exists( FunctionCall fc |
        sink.asExpr() = fc.getArgument(2) and
        fc.getTarget().getName() = "memcpy"
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    node.asExpr().getEnclosingStmt() instanceof IfStmt
  }

}

module MyTaint = TaintTracking::Global<MyConfig>;
import MyTaint::PathGraph

from MyTaint::PathNode source, MyTaint::PathNode sink
where MyTaint::flowPath(source, sink) 
select sink, source, sink, "Network byte swap flows to memcpy"