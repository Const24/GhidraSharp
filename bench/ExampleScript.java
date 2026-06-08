// Example GhidraScript for the RunScript escape hatch.
// Run it via:  --run-script bench/ExampleScript.java
// Its println() output is captured and returned to the C# caller.
import ghidra.app.script.GhidraScript;

public class ExampleScript extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("program: " + currentProgram.getName());
        println("language: " + currentProgram.getLanguageID());
        println("functions: " + currentProgram.getFunctionManager().getFunctionCount());
    }
}
