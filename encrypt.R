# get the input passed from the shell script
args <- commandArgs(trailingOnly = TRUE)
str(args)
cat(args, sep = "\n")

# test if there is at least one argument: if not, return an error
if (length(args) == 0) {
  stop("At least one argument must be supplied (input file).\n", call. = FALSE)
} else {
  print(paste0("Arg input:  ", args[1]))
}

staticryptR::staticryptr(
  files = "docs/",
  directory = ".",
  password = args[1],
  recursive = TRUE,
  template_color_primary = "#041e42",
  template_color_secondary = "#f9f9f3",
  template_title = "Protected Content",
  template_instructions = "Enter the password or contact example@email.com",
  template_button = "Access"
)

# Docs
# https://cran.r-project.org/web/packages/staticryptR/readme/README.html
# How secure is it? https://github.com/robinmoisson/staticrypt?tab=readme-ov-file#is-it-secure