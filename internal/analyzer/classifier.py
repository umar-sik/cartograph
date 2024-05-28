import ast
import sys

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score


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
    reduced_vectors = pca.fit_transform(vectors)
    num_features_before = vectors.shape[1]
    num_features_after = reduced_vectors.shape[1]
    print(f"Number of features before PCA: {num_features_before}")
    print(f"Number of features retained by PCA: {num_features_after}")

    # Calculate the maximum k value as 1 less than the number of reduced features, or 1 less than the total number of
    # samples, whichever is smaller.
    max_k = min(num_features_after - 1, len(df) - 1)

    # Perform k-means clustering with the silhouette method to find the optimal k value
    print(f"Finding optimal k value for k-means clustering between 2 and {max_k}...")
    k_values = range(2, max_k + 1)
    silhouette_scores = []

    for k in k_values:
        kmeans = KMeans(n_clusters=k, n_init=10, random_state=42)
        cluster_labels = kmeans.fit_predict(reduced_vectors)
        silhouette_avg = silhouette_score(reduced_vectors, cluster_labels)
        silhouette_scores.append(silhouette_avg)

    optimal_k = k_values[silhouette_scores.index(max(silhouette_scores))]
    print(f"Optimal k value: {optimal_k}")
    kmeans = KMeans(n_clusters=optimal_k, n_init=10, random_state=42)
    cluster_labels = kmeans.fit_predict(reduced_vectors)

    # Save the cluster ID values and corresponding labels to a new CSV file
    print("Saving cluster ID values and labels to CSV...")
    output_df = pd.DataFrame({'label': df['label'], 'cluster_id': cluster_labels})
    output_df.to_csv('cluster_output.csv', index=False)

    # Display the clusters in a graph using a scatter plot
    print("Displaying clusters in a graph...")
    plt.scatter(reduced_vectors[:, 0], reduced_vectors[:, 1], c=cluster_labels, cmap='viridis')
    plt.title('Clusters of Similar Vectors')
    plt.xlabel('First Principal Component')
    plt.ylabel('Second Principal Component')
    plt.show()


def main():
    if len(sys.argv) != 2:
        print("Usage: python vector_analysis.py </absolute/path/to/vectors.csv>")
        sys.exit(1)

    csv = sys.argv[1]
    vector_analysis(csv)


if __name__ == "__main__":
    main()
