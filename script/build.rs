use sp1_build::build_program_with_args;

fn main() {
    build_program_with_args("../program/unit", Default::default());   //build unit program
    build_program_with_args("../program/recursive", Default::default()); //build recursive program
}
