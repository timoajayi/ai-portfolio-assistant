# Timothy Ajayi

## Professional Profile

Timothy Ajayi is an AI Engineer based in Germany with a background in engineering, project management, and operations.

He transitioned into AI engineering through intensive training in Data Science, Machine Learning, and AI Engineering.

His current technical focus includes machine learning, LLM applications, Retrieval-Augmented Generation (RAG), agentic AI, APIs, and production-oriented AI engineering.

He is interested in building practical AI systems that connect machine learning and generative AI with real applications.

## Technical Skills

### AI and Machine Learning

- Python
- Scikit-learn
- XGBoost
- LightGBM
- TensorFlow
- Time-series forecasting
- Classification
- Model evaluation

### Generative AI

- Large Language Models (LLMs)
- Retrieval-Augmented Generation (RAG)
- Agentic AI
- Prompt Engineering
- Tool Calling
- LangGraph

### Backend and Data

- FastAPI
- PostgreSQL
- SQL
- REST APIs
- Pandas
- dbt

### MLOps and Infrastructure

- Docker
- MLflow
- Prefect
- DVC
- Git
- CI/CD
- Prometheus
- Grafana

## Projects

### BundesHost Tourism Forecasting

BundesHost is an end-to-end tourism forecasting platform for predicting overnight stays across Germany's 16 federal states.

The project generated state-level forecasts with a 12-month forecasting horizon.

BundesHost was developed as a team project. The team experimented with multiple forecasting approaches including SARIMA, SARIMAX, XGBoost, recurrent neural networks, and LSTM-based models.

The system used PostgreSQL and dbt for data workflows, MLflow for experiment tracking, Prefect for workflow orchestration, FastAPI for serving forecasting data, Docker for containerization, and Streamlit for the user interface.

Timothy's individual contributions included:

- Developing FastAPI endpoints for serving tourism forecasts, historical data, and state-level information.

- Integrating the Streamlit frontend with the FastAPI backend so the interface consumed forecasting data through the API.

- Setting up MLflow for experiment tracking and model development workflows.

- Working with Docker to containerize and connect components of the application.

- Contributing to integrating the forecasting pipeline into an end-to-end application.

The project achieved forecasting error below 10 percent for 15 of Germany's 16 federal states.

### Customer Churn Prediction

Customer Churn Prediction was developed as a solo project, covering the end-to-end machine learning workflow from data exploration to deployment through an interactive application.

The project used machine learning to identify customers at risk of leaving a business.

The dataset contained approximately 10,000 customers, with churners representing approximately 20 percent of the dataset.

Multiple classification approaches were compared, including logistic regression, decision trees, random forests, gradient boosting, XGBoost, LightGBM, and a neural network.

Class imbalance was addressed using techniques including SMOTE, class weighting, and model-specific weighting.

Models were evaluated using recall, F1 score, ROC-AUC, and accuracy rather than relying on accuracy alone.

Classification threshold tuning was also explored to improve the identification of customers at risk of churn.

A Streamlit application was built to expose churn predictions through an interactive interface.

### AI Project Status Agent

AI Project Status Agent was developed as a solo agentic AI project for answering project-management questions using structured project data.

The application goes beyond a standard chatbot by allowing the language model to dynamically select and call tools based on the user's request.

The agent was built using Python, LangChain, Google Gemini, Streamlit, and structured JSON project data.

The agent has access to dedicated tools for:

- Retrieving project status, ownership, progress, dates, and risks.
- Retrieving project milestones and milestone status.
- Retrieving project KPIs, targets, and current values.
- Retrieving portfolio-level information across multiple projects.

For simple questions, the agent can select and execute a single tool. For more complex requests such as management briefings, it can combine information from multiple tools before generating the final response.

The language model does not directly access the project data. Instead, Python tools retrieve structured information from the project dataset, and the returned tool results are used by the model to generate grounded responses.

A Streamlit interface provides the conversational user experience and also displays which tools were selected by the agent.

Guardrails were added so that factual project claims must be based on information returned by the available tools. Unknown projects and unavailable information are reported rather than invented.

The application was tested across single-tool retrieval, multi-tool orchestration, portfolio-level queries, unknown projects, and unavailable-information scenarios.

### AI Creative Studio

AI Creative Studio is a generative AI application designed for creating and comparing marketing imagery.

The application combines a FastAPI backend, Streamlit interface, and ComfyUI image-generation workflow.

Users can configure image-generation parameters, generate multiple images, compare outputs, and review generation history.

### AI Portfolio Assistant

The AI Portfolio Assistant is a solo AI engineering project being developed to allow portfolio visitors to ask questions about Timothy's projects, technical skills, experience, and engineering background.

The application uses a Python FastAPI backend and Google Gemini for response generation.

Portfolio information is stored as a structured knowledge source and divided into retrieval chunks.

The retrieval system uses a hybrid search architecture combining Gemini semantic embeddings with BM25 lexical retrieval.

Query expansion is used to improve retrieval when a visitor's wording differs from terminology used in the portfolio knowledge.

For each visitor question, the system retrieves the most relevant portfolio chunks and provides them to the language model as context for generating a grounded response.

A retrieval evaluation suite is used to test whether the correct evidence appears within the top retrieved chunks.

During development, evaluation identified a retrieval failure for a question about which project Timothy built independently. Adding BM25 lexical retrieval to the semantic retrieval pipeline improved Recall@3 on the current evaluation set from 87.5 percent to 100 percent.

The FastAPI chat endpoint connects retrieval with response generation, creating an end-to-end Retrieval-Augmented Generation pipeline.

The project is still in development. The backend RAG system is functional, while integration with the portfolio website frontend and deployment remain to be completed.

### Industrial AI Operations Copilot

The Industrial AI Operations Copilot is a planned portfolio project currently in development.

The goal is to build an AI-assisted system that helps engineers investigate machine behavior, analyze abnormal operating conditions, retrieve relevant technical documentation, and explain findings.

The planned system will explore machine learning, industrial telemetry, Retrieval-Augmented Generation, tool calling, agentic AI, backend development, and deployment.

It should not be presented as a completed project.

## Professional Background

Before moving into AI engineering, Timothy worked in project management and operational environments.

His experience included coordinating workflows, supporting operational processes, and working across teams.

He also has an engineering foundation from mechanical engineering studies and practical technical experience in aircraft maintenance and automotive environments.

This background contributed to his interest in building and improving technical systems.

## Current Focus

Timothy is currently developing his skills and portfolio in:

- Applied AI engineering
- Large Language Models
- Retrieval-Augmented Generation
- Agentic AI
- Machine learning
- MLOps
- Backend AI systems
- Production-oriented AI applications

## Languages

- English: Fluent
- German: B1, currently progressing toward B2

## Assistant Guidelines

When answering questions about Timothy:

- Use the portfolio information provided here as the source of truth.
- Do not invent projects, experience, skills, employers, qualifications, or results.
- Clearly distinguish completed projects from projects that are still in development.
- If information is not available in the portfolio knowledge, say that the information is not currently available.
- Keep answers concise and useful for recruiters, hiring managers, and technical visitors.