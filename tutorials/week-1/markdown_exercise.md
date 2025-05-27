# R Markdown & Gapminder: Practice Exercises

## Introduction

In this session, you will practice writing R Markdown documents and performing basic data analysis using the `gapminder` dataset. You will create a report that includes formatted text, code chunks, tables, and plots. By the end, you should be comfortable with integrating R code and Markdown in a reproducible document.

------------------------------------------------------------------------

## 1. Setup (5 minutes)

-   **Create a new R Markdown document** called `gapminder_report.qmd` in your `content/week-2` folder.
-   Edit the YAML header to include:
    -   A custom title (e.g., “Gapminder Data Exploration”)
    -   Your name as the author
    -   The current date
    -   Output format as HTML

------------------------------------------------------------------------

## 2. Markdown Formatting Practice (10 minutes)

In the document, under the title, write a short introduction (2–3 sentences) explaining what the gapminder dataset is. Practice the following Markdown features: - Make the dataset name **bold**. - Italicize the word “demographics”. - Add a [link to the gapminder website](https://www.gapminder.org/data/). - Create a bullet list of at least three variables in the dataset (e.g., country, year, lifeExp).

------------------------------------------------------------------------

## 3. Loading Data and Exploring Structure (10 minutes)

-   Insert a code chunk to load the `gapminder` library and display the first 6 rows of the dataset.
-   Add a code chunk to show the structure (`str()`) of the dataset.
-   Write a short paragraph (Markdown) interpreting what you see.

------------------------------------------------------------------------

## 4. Basic Data Summaries (10 minutes)

-   Add a code chunk to calculate:
    -   The number of unique countries in the dataset.
    -   The range of years covered.
    -   The average life expectancy globally.
-   Summarize your findings in a Markdown paragraph, using inline R code for the summary statistics.

------------------------------------------------------------------------

## 5. Data Visualization (10 minutes)

-   Add a code chunk to create a plot of average life expectancy over time (global average).
-   Add another code chunk to plot life expectancy for a single country (choose one).
-   Use chunk options to hide the code for the country-specific plot (`echo = FALSE`).
-   Add captions or explanations for each plot using Markdown.

------------------------------------------------------------------------

## 6. Parameterisation (10 minutes)

-   Edit your YAML to add a parameter for `country` (default: “United Kingdom”).
-   Update your code so that the country-specific plot uses the parameter value.
-   Add a sentence in Markdown explaining how changing the parameter affects the report.

------------------------------------------------------------------------

## 7. Knitting and Submission (5 minutes)

-   Knit your document to HTML.
-   Check that all code, plots, and text display correctly.
-   Submit your knitted HTML file as instructed.

------------------------------------------------------------------------

## Extension (if time allows)

-   Add a table showing the top 5 countries by life expectancy in the most recent year.
-   Experiment with other Markdown features: blockquotes, images, or tables.
