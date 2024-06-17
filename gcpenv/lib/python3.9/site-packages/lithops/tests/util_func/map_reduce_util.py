def simple_reduce_function(results):
    """general purpose reduce function that sums up the results
    of previous activations of map functions  """
    total = 0
    for map_result in results:
        total = total + map_result
    return total


def my_reduce_function(results):
    """sums up the number of words by totaling the number of appearances of each word.
    @param results: dictionary that counts the appearances of each word within a url."""
    final_result = 0
    for count in results:
        for word in count:
            final_result += count[word]
    return final_result
