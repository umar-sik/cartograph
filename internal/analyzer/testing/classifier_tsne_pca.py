import ast
import sys

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
from sklearn.metrics import silhouette_score


# This is not as good as without t-SNE, but t-SNE does make visualization much nicer.
def vector_analysis(csv_file):
    # Load the CSV file into a pandas DataFrame
    print("Loading data from CSV...")
    df = pd.read_csv(csv_file)

    # Convert the string representation of the vectors into lists of floats
    print("Processing vectors...")
    df['vector'] = df['vector'].apply(lambda x: np.array(ast.literal_eval(x.replace('{', '[').replace('}', ']'))))
    print(f"Total number of vectors: {len(df)}")

    # Convert lists of floats into a NumPy array
    vectors = np.array(df['vector'].to_list())

    # Perform PCA and select the optimal number of principal components
    print("Performing PCA...")
    pca = PCA(n_components=0.95)
    reduced_vectors_pca = pca.fit_transform(vectors)
    num_features_before = vectors.shape[1]
    num_features_after = reduced_vectors_pca.shape[1]
    print(f"Number of features before PCA: {num_features_before}")
    print(f"Number of features retained by PCA: {num_features_after}")

    # Find optimal t-SNE hyperparameters using grid search and KL divergence
    print("Finding optimal t-SNE hyperparameters...")
    perplexities = [10, 30, 50, 100]
    learning_rates = [10, 100, 200, 500, 1000]
    best_kl_divergence = float('inf')
    best_hyperparams = None

    for perplexity in perplexities:
        for learning_rate in learning_rates:
            tsne = TSNE(n_components=2, perplexity=perplexity, learning_rate=learning_rate, random_state=11)
            reduced_vectors_tsne = tsne.fit_transform(reduced_vectors_pca)
            kl_divergence = tsne.kl_divergence_
            if kl_divergence < best_kl_divergence:
                best_kl_divergence = kl_divergence
                best_hyperparams = (perplexity, learning_rate)

    print(f"Optimal t-SNE hyperparameters: Perplexity = {best_hyperparams[0]}, Learning Rate = {best_hyperparams[1]}")

    # Perform t-SNE with optimal hyperparameters
    print("Performing t-SNE with optimal hyperparameters...")
    tsne = TSNE(n_components=2, perplexity=best_hyperparams[0], learning_rate=best_hyperparams[1], random_state=42)
    reduced_vectors_tsne = tsne.fit_transform(reduced_vectors_pca)

    # Calculate the maximum k value as 1 less than the number of reduced features, or 10, whichever is larger
    max_k = max(num_features_after - 1, 10)

    # Perform k-means clustering with the silhouette method to find the optimal k value
    print(f"Finding optimal k value for k-means clustering between 2 and {max_k}...")
    k_values = range(2, max_k + 1)
    silhouette_scores = []

    for k in k_values:
        kmeans = KMeans(n_clusters=k, n_init=10, random_state=42)
        cluster_labels = kmeans.fit_predict(reduced_vectors_tsne)
        silhouette_avg = silhouette_score(reduced_vectors_tsne, cluster_labels)
        silhouette_scores.append(silhouette_avg)

    optimal_k = k_values[silhouette_scores.index(max(silhouette_scores))]
    print(f"Optimal k value: {optimal_k}")
    kmeans = KMeans(n_clusters=optimal_k, n_init=10, random_state=42)
    cluster_labels = kmeans.fit_predict(reduced_vectors_tsne)

    # Save the cluster ID values and corresponding labels to a new CSV file
    print("Saving cluster ID values and labels to CSV...")
    output_df = pd.DataFrame({'label': df['label'], 'cluster_id': cluster_labels})
    output_df.to_csv('cluster_output.csv', index=False)

    # Display the clusters in a graph using a scatter plot with t-SNE data
    print("Displaying clusters in a graph...")
    plt.scatter(reduced_vectors_tsne[:, 0], reduced_vectors_tsne[:, 1], c=cluster_labels, cmap='viridis')
    plt.title('Clusters of Similar Vectors')
    plt.xlabel('t-SNE 1')
    plt.ylabel('t-SNE 2')
    plt.show()


def main():
    if len(sys.argv) != 2:
        print("Usage: python vector_analysis.py </absolute/path/to/vectors.csv>")
        sys.exit(1)

    csv = sys.argv[1]
    vector_analysis(csv)


if __name__ == "__main__":
    main()
